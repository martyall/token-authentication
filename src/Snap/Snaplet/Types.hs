{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE DeriveTraversable #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}

module Snap.Snaplet.Types where

--import Control.Alternative

import qualified Data.Aeson as A
import Control.Lens
import Control.Applicative
import Control.Monad
import Control.Monad.IO.Class
import Control.Monad.Reader.Class
import Data.ByteString.Lazy
import Data.Time
import qualified Data.Text as T
import Control.Monad.Time
import Data.Monoid
import Data.Foldable
import Data.Traversable
import Crypto.JOSE        as Jose
import Crypto.JWT         as Jose
import Snap.Core
import Snap

import System.IO.Unsafe
import GHC.Generics

data IsMatch = Matches | DoesNotMatch
  deriving (Eq, Show, Read, Generic, Ord)


data AuthResult val
  = BadPassword
  | NoSuchUser
  -- | Authentication succeeded.
  | Authenticated val
  -- | If an authentication procedure cannot be carried out - if for example it
  -- expects a password and username in a header that is not present -
  -- @Indefinite@ is returned. This indicates that other authentication
  -- methods should be tried.
  | Indefinite
  deriving (Eq, Show, Read, Generic, Ord, Functor, Traversable, Foldable)

instance Monoid (AuthResult val) where
  mempty = Indefinite
  Indefinite `mappend` x = x
  x `mappend` _ = x

instance Applicative AuthResult where
  pure = return
  (<*>) = ap

instance Monad AuthResult where
  return = Authenticated
  Authenticated v >>= f = f v
  BadPassword  >>= _ = BadPassword
  NoSuchUser   >>= _ = NoSuchUser
  Indefinite   >>= _ = Indefinite

instance Alternative AuthResult where
  empty = mzero
  (<|>) = mplus

instance MonadPlus AuthResult where
  mzero = mempty
  mplus = (<>)


-- | An @AuthCheck@ is the function used to decide the authentication status
-- (the 'AuthResult') of a request. Different @AuthCheck@s may be combined as a
-- Monoid or Alternative; the semantics of this is that the *first*
-- non-'Indefinite' result from left to right is used.
data AuthCheck m val = AuthCheck
  { runAuthCheck :: Request -> m (AuthResult val) } deriving (Functor)


--instance Functor AuthCheck where
--  fmap f (AuthCheck handler) = AuthCheck $ \req -> fmap (fmap f) $ handler req

instance Monad m => Monoid (AuthCheck m val) where
  mempty = AuthCheck $ const $ return mempty
  AuthCheck f `mappend` AuthCheck g = AuthCheck $ \x -> do
    fx <- f x
    gx <- g x
    return $ fx <> gx

instance Monad m => Applicative (AuthCheck m) where
  pure = return
  (<*>) = ap

instance Monad m => Monad (AuthCheck m) where
  return = AuthCheck . return . return . return
  fail _ = AuthCheck . const $ return Indefinite
  AuthCheck ac >>= f = AuthCheck $ \req -> do
    aresult <- ac req
    case aresult of
      Authenticated usr -> runAuthCheck (f usr) req
      BadPassword       -> return BadPassword
      NoSuchUser        -> return NoSuchUser
      Indefinite        -> return Indefinite

instance MonadIO m => MonadIO (AuthCheck m) where
  liftIO action = AuthCheck $ const $ Authenticated <$> liftIO action

instance MonadIO m => MonadTime (AuthCheck m) where
  currentTime = liftIO getCurrentTime

instance Monad m => Alternative (AuthCheck m) where
  empty = mzero
  (<|>) = mplus

instance Monad m => MonadPlus (AuthCheck m) where
  mzero = mempty
  mplus = (<>)

-- | @JWTSettings@ are used to generate cookies, and to verify JWTs.
data JWTSettings = JWTSettings
  { key             :: Jose.JWK
  -- | An @aud@ predicate. The @aud@ is a string or URI that identifies the
  -- intended recipient of the JWT.
  , audienceMatches :: Jose.StringOrURI -> IsMatch
  } deriving (Generic)

-- | A @JWTSettings@ where the audience always matches.
defaultJWTSettings :: Jose.JWK -> JWTSettings
defaultJWTSettings k = JWTSettings { key = k, audienceMatches = const Matches }

jwtSettingsToJwtValidationSettings :: JWTSettings -> Jose.JWTValidationSettings
jwtSettingsToJwtValidationSettings s
  = defaultJWTValidationSettings
       & audiencePredicate .~ (toBool <$> audienceMatches s)
  where
    toBool Matches = True
    toBool DoesNotMatch = False

theKey :: JWK
theKey = unsafePerformIO . genJWK $ OctGenParam 256
{-# NOINLINE theKey #-}

data Token = Token { getToken :: ByteString }

instance A.ToJSON Token where
  toJSON (Token tok) = A.object [ "token" A..= (T.pack . show $ tok) ]
