{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE DeriveGeneric #-}

module Snap.Snaplet.Authentication where

import           Data.Text                  (Text)
import           Data.UUID                  (UUID)
import           Data.UUID.Aeson
import           Control.Lens
import           Control.Monad.Except
import           Control.Monad.Reader
import qualified Crypto.JOSE          as Jose
import qualified Crypto.JWT           as Jose
import           Crypto.Util          (constTimeEq)
import           Data.Aeson           (FromJSON, Result (..), ToJSON, fromJSON,
                                       toJSON)
import qualified Data.ByteString      as BS
import qualified Data.ByteString.Lazy as BSL
import qualified Data.HashMap.Strict  as HM
import qualified Data.Text            as T
import           Data.Time            (UTCTime)
import           Snap.Core
import           GHC.Generics

import           Snap
import           Snap.Snaplet.Types
import qualified Snap.Types.Headers as HD

----------------------------------------------------------------------------------------------------------------------------------------------------------------
-- This should probably also be from ClaimSet
--
-- | How to decode data from a JWT.
--
-- The default implementation assumes the data is stored in the unregistered
-- @dat@ claim, and uses the @FromJSON@ instance to decode value from there.
class FromJWT a where
  decodeJWT :: Jose.JWT -> Either T.Text a
  default decodeJWT :: FromJSON a => Jose.JWT -> Either T.Text a
  decodeJWT m = case HM.lookup "dat" (Jose._unregisteredClaims $ Jose.jwtClaimsSet m ) of
    Nothing -> Left "Missing 'dat' claim"
    Just v  -> case fromJSON v of
      Error e -> Left $ T.pack e
      Success a -> Right a

-- | How to encode data from a JWT.
--
-- The default implementation stores data in the unregistered @dat@ claim, and
-- uses the type's @ToJSON@ instance to encode the data.
class ToJWT a where
  encodeJWT :: a -> Jose.ClaimsSet
  default encodeJWT :: ToJSON a => a -> Jose.ClaimsSet
  encodeJWT a = Jose.addClaim "dat" (toJSON a) Jose.emptyClaimsSet

instance FromJWT UUID
instance ToJWT UUID

instance ToJWT Text
instance FromJWT Text

jwtAuthCheck :: (MonadSnap m, FromJWT usr) => JWTSettings -> AuthCheck m usr
jwtAuthCheck config = do
  req <- AuthCheck $ \x -> return (Authenticated x) -- can't use reader inside monadsnap
  token <- maybe mempty return $ do
    authHdr <- HD.lookup "Authorization" $ headers req
    let bearer = "Bearer "
        (mbearer, rest) = BS.splitAt (BS.length bearer) authHdr
    guard (mbearer `constTimeEq` bearer)
    return rest
  verifiedJWT <- liftIO $ runExceptT $ do
    unverifiedJWT <- Jose.decodeCompact $ BSL.fromStrict token
    Jose.validateJWSJWT (jwtSettingsToJwtValidationSettings config)
                        (key config)
                        unverifiedJWT
    return unverifiedJWT
  case verifiedJWT of
    Left (_ :: Jose.JWTError) -> mzero
    Right v -> case decodeJWT v of
      Left _ -> mzero
      Right v' -> return v'

-- | Creates a JWT containing the specified data. The data is stored in the
-- @dat@ claim. The 'Maybe UTCTime' argument indicates the time at which the
-- token expires.
makeJWT :: (ToJWT a, MonadSnap m)
  => a -> JWTSettings -> Maybe UTCTime -> m (Either Jose.Error BSL.ByteString)
makeJWT v cfg expiry = liftIO . runExceptT $ do
  ejwt <- Jose.createJWSJWT (key cfg)
                            (Jose.newJWSHeader (Jose.Protected, Jose.HS256))
                            (addExp $ encodeJWT v)
  Jose.encodeCompact ejwt
  where
   addExp claims = case expiry of
     Nothing -> claims
     Just e  -> claims & Jose.claimExp .~ Just (Jose.NumericDate e)


initAuthTokenManager :: SnapletInit b JWTSettings
initAuthTokenManager =
    makeSnaplet "AuthHeaderSession"
                "A snaplet providing sessions via authorization header"
                Nothing $ return $ defaultJWTSettings theKey

class HasJWTSettings m where
  getJWTSettings :: m JWTSettings
