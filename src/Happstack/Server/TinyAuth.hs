{-# LANGUAGE TemplateHaskell, DeriveDataTypeable, FlexibleContexts, TypeFamilies #-}
{-| A simple framework for doing forms-based
authenitcation in Happstack.
-}
module Happstack.Server.TinyAuth
    (
    -- * Required state
      AuthConfig(..)
    , defaultAuthConfig
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
    -- * Monadic interface
    ,  AuthMonad(..)
    , setLoggedIn'
    , forwardAfterLogin'
    , loginData'
    , requireLoggedIn'
    , setLoggedOut'
    , refreshLoggedIn'
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
import Data.Text (Text)
import qualified Data.Text as T
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
-- 'defaultAuthConfig' value.
data AuthConfig s =
    MkAuthConfig
     { loginForm   :: Text -- ^ where to redirect to on authentication failure
     , loginSecret :: Maybe Key -- ^ key to use for encryption
     , loginCookieName
         :: String -- ^ Name of cookie to store authentication data
     , loginRedirectParam
         :: Maybe String -- ^ Query param used to store redirect information
     }

defaultAuthConfig :: AuthConfig s
defaultAuthConfig =
    MkAuthConfig
     { loginForm = T.pack "/login"
     , loginSecret = Nothing
     , loginCookieName = "authData"
     , loginRedirectParam = Just "loginRedirect"
     }

-- | Class to make both the 'AuthConfig' data available and to perform Happstack-server
-- functions.
class ( MonadIO m, FilterMonad Response m, ServerMonad m, HasRqData m, Functor m
      , WebMonad Response m)
         => AuthMonad m where
    type Session m
    getAuthConfig :: m (AuthConfig (Session m))

newExpires :: AuthConfig s -> IO UTCTime
newExpires _ = do
  curr <- liftIO getCurrentTime
  -- expires in one week
  return $ addUTCTime 604800 curr

getKey_ :: AuthConfig s -> IO Key
getKey_ cfg =
  case loginSecret cfg of
    Just k -> return k
    Nothing -> getDefaultKey

-- | The passed in user-data is sent to the client
-- encrypted. Call this in the handler for your login form after
-- the user has successfully provided credentials.
setLoggedIn :: (SafeCopy s, MonadIO m, FilterMonad Response m, Functor m)
            => AuthConfig s -- ^ Config
            -> s            -- ^ Session state
            -> m ()
setLoggedIn cfg user = do
  let cName = loginCookieName cfg
  expires <- liftIO $ newExpires cfg
  let dt = MkSessionInfo user expires
      dtBytes = runPut $ safePut dt
  key <- liftIO $ getKey_ cfg
  cData <- B8.unpack <$> (liftIO $ encryptIO key dtBytes)
  let cookie = (mkCookie cName cData) {httpOnly = True}
  addCookie (Expires expires) cookie

-- | Wrapper around `setLoggedIn`.
setLoggedIn' :: (AuthMonad m, Session m ~ s, SafeCopy s)
             => s -> m ()
setLoggedIn' s = getAuthConfig >>= flip setLoggedIn s


eitherToMaybe :: Either a b -> Maybe b
eitherToMaybe Left{}  = Nothing
eitherToMaybe (Right x) = Just x

-- | If there is a logged in user and the session data
-- is valid return the session data.
loginData :: (SafeCopy s, MonadIO m, HasRqData m, ServerMonad m)
          => AuthConfig s
          -> m (Maybe s)
loginData cfg = do
  let cName = loginCookieName cfg
  cookieE <- getDataFn $ lookCookie cName
  key <- liftIO $ getKey_ cfg
  currTime <- liftIO getCurrentTime
  return $
   do cookie <- eitherToMaybe cookieE 
      bytes <- decrypt key $ B8.pack $ cookieValue cookie
      sessData <- eitherToMaybe $ runGet safeGet bytes
      guard $ sess_expires sessData > currTime
      return $ sess_user sessData

-- | Wrapper around `loginData`.
loginData' :: (AuthMonad m, Session m ~ s, SafeCopy s)
           => m (Maybe s)
loginData' = getAuthConfig >>= loginData

-- | Return a redirect to send the user back where they were
-- trying to go when they were bounced to the login form.
-- NOTE: You'll lose any post-body data the user was trying
-- to submit, so try to require login on the form GET as
-- well as the form POST.
forwardAfterLogin :: (HasRqData m, FilterMonad Response m, Functor m)
                  => AuthConfig s
                  -> String -- ^ default redirect url
                  -> m Response
forwardAfterLogin cfg defaultUrl = do
  urlStr <- redirectUrl cfg defaultUrl
  seeOther urlStr (toResponse ())

-- | Wrapper around `forwardAfterLogin`.
forwardAfterLogin' :: (AuthMonad m)
                   => String -- ^ default redirect url
                   -> m Response
forwardAfterLogin' defaultUrl
    = getAuthConfig >>= flip forwardAfterLogin defaultUrl

redirectUrl :: (HasRqData m, Monad m, Functor m)
            => AuthConfig s
            -> String       -- ^ default redirect location
            -> m String
redirectUrl cfg def =
  case loginRedirectParam cfg of
    Nothing -> return def
    Just redirectParam
        -> do
      redirectStr <- queryString $ look redirectParam
      case importURL redirectStr of
        Just url@(URL {url_type=HostRelative}) ->
            return $ exportURL url
        _ -> return $ def

-- | Pack the current request path into the login
-- URL provide by the config.
createLoginUrl :: (HasRqData m, ServerMonad m, Functor m)
               => AuthConfig s
               -> m String
createLoginUrl cfg = do
  let urlStr = T.unpack $ loginForm cfg
  let paramM = loginRedirectParam cfg
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
requireLoggedIn :: (SafeCopy s, MonadIO m, HasRqData m, ServerMonad m,
                    WebMonad Response m, FilterMonad Response m, Functor m)
                => AuthConfig s
                -> m s
requireLoggedIn cfg = do
  userM <- loginData cfg
  case userM of
    Just user -> return user
    Nothing -> do
        url <- createLoginUrl cfg
        seeOther url (toResponse ()) >>=
          finishWith

-- | Wrapper around `requireLoggedIn`.
requireLoggedIn' :: (AuthMonad m, Session m ~ s, SafeCopy s)
                 => m s
requireLoggedIn' = getAuthConfig >>= requireLoggedIn

-- | If a user is logged in, log them out.
-- We do not gaurantee this succeeds for a malicious
-- user agent - it is provided for user-agent convinience only,
-- or for a user-agent choosing to lock itself down.
setLoggedOut :: (SafeCopy s, MonadIO m, FilterMonad Response m, HasRqData m, ServerMonad m)
             => AuthConfig s -> m ()
setLoggedOut cfg = do
  userM <- loginData cfg
  case userM of
    Nothing -> return ()
    Just{} -> do
      let name = loginCookieName cfg
      addCookie Expired $ mkCookie name ""

-- | Wrapper around `setLoggedOut`.
setLoggedOut' :: (AuthMonad m, Session m ~ s, SafeCopy s)
              => m ()
setLoggedOut' = getAuthConfig >>= setLoggedOut

-- | If a user is logged in, refresh their login cookie so they
-- can stay logged in. Used for keeping a user active when you want
-- to log them out after X minutes for inactivity.
refreshLoggedIn :: (SafeCopy s, MonadIO m, FilterMonad Response m, HasRqData m, ServerMonad m, Functor m)
                => AuthConfig s -> m ()
refreshLoggedIn cfg = do
  sessM <- loginData cfg
  case sessM of
    Nothing -> return ()
    Just sess -> setLoggedIn cfg sess

-- | Wrapper around `refreshLoggedIn`.
refreshLoggedIn' :: (AuthMonad m, Session m ~ s, SafeCopy s)
                 => m ()
refreshLoggedIn' = getAuthConfig >>= refreshLoggedIn
