{-# LANGUAGE TemplateHaskell, DeriveDataTypeable, FlexibleContexts #-}

{-| A simple framework for doing forms-based
authenitcation in Happstack.
-}
module Happstack.Server.TinyAuth
    (
    -- * Required state
      AuthMonad(..)
    , AuthState(..)
    , defaultAuthState
    -- * Key management
    , getKey
    , defaultKeyFile
    , getDefaultKey
    , initKey
    -- * System hooks, login/logout
    , setLoggedIn
    , forwardAfterLogin
    , loginData
    , requireLoggedIn
    , setLoggedOut
    , refreshLoggedIn
    ) where

import Control.Monad (guard)
import Control.Monad.Trans (MonadIO, liftIO)
import qualified Data.ByteString.Char8 as B8
import Data.Data (Data)
import Data.Functor
import Data.Maybe (fromMaybe)
import Data.Proxy (Proxy, asProxyTypeOf)
import Data.SafeCopy (base, deriveSafeCopy, SafeCopy, safePut, safeGet)
import Data.Serialize (runGet, runPut)
import Data.Time (UTCTime, getCurrentTime, addUTCTime)
import Data.Typeable (Typeable)
import Happstack.Server
    ( FilterMonad, ServerMonad, WebMonad, Response, HasRqData, getDataFn,
      lookCookie, addCookie, mkCookie, Cookie(..), CookieLife(..),
      finishWith, seeOther, toResponse, look, queryString, rqUri, askRq )
import Network.URL
    ( URL(..), URLType(..), importURL, exportURL, add_param)
import Web.ClientSession

-- | Internal type we serialize to the
-- user cookie.
data SessionInfo u =
    MkSessionInfo
    { sess_user    :: u
    , sess_expires :: UTCTime
    }
 deriving (Data, Typeable, Eq, Ord)

deriveSafeCopy 1 'base ''SessionInfo

-- | This type is used to customize how authentication
-- works for your site. We recommend building it from the
-- 'defaultAuthState' value.
data AuthState =
    MkAuthState
     { loginForm   :: String -- ^ where to redirect to on authentication failure
     , loginSecret :: Maybe Key -- ^ key to use for encryption
     , loginCookieName
         :: String -- ^ Name of cookie to store authentication data
     , loginRedirectParam
         :: Maybe String -- ^ Query param used to store redirect information
     }

defaultAuthState =
    MkAuthState { loginForm = "/login"
                , loginSecret = Nothing
                , loginCookieName = "authData"
                , loginRedirectParam = Just "loginRedirect"
                }

-- | Class to make both the 'AuthState' data available and to perform Happstack-server
-- functions.
class ( MonadIO m, FilterMonad Response m, ServerMonad m, HasRqData m, Functor m
      , WebMonad Response m)
         => AuthMonad m where
    getAuthState :: m AuthState

authCookieName :: AuthMonad m => m String
authCookieName = loginCookieName <$> getAuthState

authRedirectParam :: AuthMonad m => m (Maybe String)
authRedirectParam = loginRedirectParam <$> getAuthState

newExpires :: AuthMonad m => m UTCTime
newExpires = do
  curr <- liftIO getCurrentTime
  -- expires in one week
  return $ addUTCTime 604800 curr

getKey' :: AuthMonad m => m Key
getKey' = do
  mKey <- loginSecret <$> getAuthState
  case mKey of
    Just k -> return k
    Nothing -> liftIO getDefaultKey

-- | The passed in user-data is sent to the client
-- encrypted. Call this in the handler for your login form after
-- the user has successfully provided credentials.
setLoggedIn :: (SafeCopy user, AuthMonad m)
            => user -> m ()
setLoggedIn user = do
  cName <- authCookieName
  expires <- newExpires
  let dt = MkSessionInfo user expires
      dtBytes = runPut $ safePut dt
  key <- getKey'
  cData <- B8.unpack <$> (liftIO $ encryptIO key dtBytes)
  let cookie = (mkCookie cName cData) {httpOnly = True}
  addCookie (Expires expires) cookie

eitherToMaybe :: Either a b -> Maybe b
eitherToMaybe Left{}  = Nothing
eitherToMaybe (Right x) = Just x

-- | If there is a logged in user and the session data
-- is valid return the session data.
loginData :: (SafeCopy user, AuthMonad m) => m (Maybe user)
loginData = do
  cName <- authCookieName
  cookieE <- getDataFn $ lookCookie cName
  key <- getKey'
  currTime <- liftIO getCurrentTime
  return $
   do cookie <- eitherToMaybe cookieE 
      bytes <- decrypt key $ B8.pack $ cookieValue cookie
      sessData <- eitherToMaybe $ runGet safeGet bytes
      guard $ sess_expires sessData > currTime
      return $ sess_user sessData

-- | Return a redirect to send the user back where they were
-- trying to go when they were bounced to the login form.
-- NOTE: You'll lose any post-body data the user was trying
-- to submit, so try to require login on the form GET as
-- well as the form POST.
forwardAfterLogin :: (AuthMonad m)
                  => String -- ^ default redirect url
                  -> m Response
forwardAfterLogin defaultUrl = do
  urlStr <- redirectUrl defaultUrl
  seeOther urlStr (toResponse ())

redirectUrl :: AuthMonad m => String -> m String
redirectUrl def = do
  paramM <- authRedirectParam
  case paramM of
    Nothing -> return def
    Just redirectParam
        -> do
      redirectStr <- queryString $ look redirectParam
      case importURL redirectStr of
        Just url@(URL {url_type=HostRelative}) ->
            return $ exportURL url
        _ -> return $ def

createLoginUrl :: AuthMonad m => m String
createLoginUrl = do
  urlStr <- loginForm <$> getAuthState
  paramM <- authRedirectParam
  currUrlStr <- rqUri <$> askRq
  let newUrlM = do
        redirectParam <- paramM
        baseUrl <- importURL urlStr
        currUrl <- importURL currUrlStr
        let redirectStr =
                exportURL $ currUrl {url_type = HostRelative}
        return $ add_param baseUrl (redirectParam, redirectStr)
  case newUrlM of
    Nothing -> return urlStr -- do what the user told us if things don't parse
    Just newUrl -> return $ exportURL newUrl

{-| Return the logged-in user. If a user is not
logged in, they are forwarded to your login page. 
-}
requireLoggedIn :: (SafeCopy user, AuthMonad m)
                => m user
requireLoggedIn = do
  userM <- loginData
  case userM of
    Just user -> return user
    Nothing -> do
        url <- createLoginUrl
        seeOther url (toResponse ()) >>=
          finishWith

-- | If a user is logged in, log them out.
-- We do not gaurantee this succeeds for a malicious
-- user agent - it is provided for user-agent convinience only,
-- or for a user-agent choosing to lock itself down.
setLoggedOut :: (AuthMonad m, SafeCopy u) => Proxy u -> m ()
setLoggedOut p = do
  userM <- loginData
  let _ = asProxyTypeOf userM (Just <$> p)
  case userM of
    Nothing -> return ()
    Just{} -> do
      name <- authCookieName
      addCookie Expired $ mkCookie name ""

-- | If a user is logged in, refresh their login cookie so they
-- can stay logged in. Used for keeping a user active when you want
-- to log them out after X minutes for inactivity.
refreshLoggedIn :: (AuthMonad m, SafeCopy u) => Proxy u -> m ()
refreshLoggedIn p = do
  userM <- loginData
  case userM of
    Nothing -> return ()
    Just user -> setLoggedIn $ asProxyTypeOf user p
