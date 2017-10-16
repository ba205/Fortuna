#!/usr/bin/env stack

import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BS8 (putStrLn, pack, lines)
import qualified Data.ByteString as BS 
  (append, empty, length, writeFile, readFile, take, copy)
import Data.Serialize (decode, encode)
import Control.Monad (when, forM, forM_, forever)
import Crypto.Hash (hash, SHA256 (..), MD4, Digest)
import Data.ByteArray (convert)
import Crypto.Cipher.AES (AES256)
import Crypto.Cipher.Types (BlockCipher (..), Cipher (..), nullIV)
import Crypto.Error (throwCryptoError)
import qualified Data.Vector.Mutable as V
import Data.IORef
import Network.Info


-- | The State of the Generator is a tuple of bytestrings. The first component
--   is the key, and the second is the counter.
type GeneratorState = IORef (ByteString, ByteString)

-- | Seed is arbtirary input data, represented as a bytestring.
type Seed = ByteString

-- | Bytestring encoded zero for convenience.
zero :: ByteString
zero = encode (0 :: Integer)

-- | Initialize the Generator's key and counter to zero.
initializeGenerator :: IO GeneratorState
initializeGenerator = newIORef (zero, zero)

-- | Helper function that increments an integer in bytestring format.
inc :: ByteString -> Either String ByteString
inc n_string = do
  n <- decode n_string :: Either String Integer
  return $ encode (n+1)

-- | Simpler version of SHA256 function from cryptonite for this use-case.
sha256 :: ByteString -> ByteString
sha256 bs = 
  let digest :: Digest SHA256
      digest = hash bs
    in convert digest :: ByteString

-- | Updates counter of Generator state using arbitrary bytestring.
--   Uses SHA256 hashing algorithm. 
reseed :: GeneratorState -> Seed -> IO (Either String GeneratorState)
reseed gState seed = do
  (key, counter) <- readIORef gState
  let newCounter = inc counter
  case newCounter of
    (Left err)   -> return $ Left err
    (Right newC) -> do
      let newKey = sha256 $ BS.append key seed
      atomicWriteIORef gState (BS.copy newKey, BS.copy newC)
      return $ Right gState

-- | Helper function to make seed 32 bits, in lieu of a KDF due to
--   time constraints.
to32 :: ByteString -> ByteString
to32 = BS.take 32 . foldr BS.append BS.empty . replicate 32

-- | Simpler AES256 function for this use case.
aes256 :: ByteString -> ByteString -> ByteString
aes256 key plaintext = 
  let context :: AES256
      context = throwCryptoError $ cipherInit $ to32 key
    in ctrCombine context nullIV plaintext

-- | Update the Generator State by incrementing the counter and using the
--   AES256 block cipher
updateGen :: IO (Either String (GeneratorState, ByteString))
          -> IO (Either String (GeneratorState, ByteString))
-- updateGen (Left err) = return $ Left err
-- updateGen (Right ((k, c), r)) = do
updateGen state = do
  s <- state
  case s of 
    Left e -> return $ Left e
    Right (gState, r) -> do
      (k, c) <- readIORef gState
      let newCounter = inc c
      case newCounter of
        Left err   -> return $ Left err
        Right newC -> do
          writeIORef gState (k, newC)
          (a, b) <- readIORef gState
          print $ BS.append r (aes256 k c)
          return $ Right (gState, BS.append r (aes256 k c))

-- | Given the Generator State and the number of blocks the user wants,
--   generate that many blocks of random output as a bytestring. Make sure that
--   the counter is non-zero, otherwise the generator has never been seeded.
generateBlocks :: GeneratorState 
               -> Int 
               -> IO (Either String (GeneratorState, ByteString))
generateBlocks gState numBlocks = do
  (key, counter) <- readIORef gState
  if counter == zero then
    return $ Left "Make sure counter of generator state is non-zero." else
      Prelude.iterate updateGen 
        (return $ Right (gState, BS.empty)) !! numBlocks
  
-- | Helper function for pseudoRandomData. Ceiling function for division by 16.
--   Usage is for m between 0 and 2^20.
bytesToBlocks :: Integral a => a -> a
bytesToBlocks m
  | m < 16          = 0  
  | m `mod` 16 == 0 = m `div` 16
  | otherwise       = (m `div` 16) + 1

-- | Given the Generator State and the number of bytes of random data to
--   generate, output a pseudorandom string of n bytes. Make sure that the 
--   number of bytes is non-negative and limited to reduce the statistical
--   deviation from perfectly random outputs.
pseudoRandomData :: GeneratorState 
                 -> Int 
                 -> IO (Either String (GeneratorState, ByteString))
pseudoRandomData gState numBytes =
  if 0 > numBytes || numBytes > 2^20 then
    return $ Left 
      "Make sure the number of bytes is non-negative and restricted to below 2^20."
  else do
    let m = bytesToBlocks numBytes
    eitherRandomOutput <- generateBlocks gState m
    case eitherRandomOutput of
      Left e -> return $ Left e
      Right r -> do
        let randomOutput = BS.take numBytes $ snd r
            genState1    = fst r
        eitherGState <- generateBlocks genState1 2
        case eitherGState of 
          Left err -> return $ Left err
          Right s -> do
            let genState2 = fst s
            return $ Right (genState2, randomOutput) 

-- | Pools of entropy stored as bytestrings in a mutable vector.
type Pools = V.IOVector ByteString

-- | The state of the pseudorandom number generator incorporates the state
--   of a generator, a reseed counter, and 32 reseeding pools.
type PRNG = (GeneratorState, IORef Int, Pools)

-- | Initialize our pseudorandom number generator.
initializePRNG :: IO PRNG
initializePRNG = do
  generatorState <- initializeGenerator
  reseedCount <- newIORef 0
  pools <- V.replicate 32 BS.empty
  return (generatorState, reseedCount, pools)

-- | Threshold for individual entropy pool size.
minPoolSize :: Int
minPoolSize = 32

-- | Output random data using entropy pools. Reseed if necessary.
randomData :: PRNG -> Int -> IO ()
randomData (gState, reseedCount, pools) numBytes = do
  p_0 <- V.read pools 0
  oldReseedCount <- readIORef reseedCount
  when (BS.length p_0 >= minPoolSize) $ do
    let newReseedCount = oldReseedCount + 1
    writeIORef reseedCount newReseedCount
    s <- newIORef BS.empty
    forM_ [0..31] (\i ->
      when (2^i `mod` newReseedCount == 0) $ do
        p_i <- V.read pools i
        s' <- readIORef s
        writeIORef s (BS.append s' (sha256 p_i))
        V.write pools i BS.empty)
    s'' <- readIORef s
    eitherGState <- reseed gState s''
    return ()
  randomData <- pseudoRandomData gState numBytes
  case randomData of
    Left e -> putStrLn e
    Right rData -> BS8.putStrLn $ snd rData

-- | Add an event from our entropy sources to one of the pools.
addRandomEvent :: PRNG -> Int -> ByteString -> IO PRNG
addRandomEvent (gState, reseedCount, pools) poolNum event =
  do
    let properEvent = BS.take 32 event
        e = encode $ BS.length properEvent
    oldPool <- V.read pools poolNum
    V.write pools poolNum 
      (BS.append oldPool (BS.append e event))
    return (gState, reseedCount, pools)

-- | Helper function to convert network interface constructors into
--   proper seeds.
interfaceToBS :: NetworkInterface -> [ByteString]
interfaceToBS 
  NetworkInterface{name = name, ipv4 = ipv4, ipv6 = ipv6, mac = mac}
  = map BS8.pack [name, show ipv4, show ipv6, show mac]

main :: IO ()
main = do
  -- initialize our CSPRNG
  (gState, reseedCount, pools) <- initializePRNG

  -- Create seeds from network interface information (name, ipv4 address,
  -- ipv6 address, mac address).
  networkInterfaces <- getNetworkInterfaces
  let networkSeeds = concatMap interfaceToBS networkInterfaces

  -- Create seeds from process information (process id, time elapsed since
  -- process spawned, process name). ps.txt is created from parent bash script.
  processInfo <- BS.readFile "ps.txt"
  let processSeeds = BS8.lines processInfo

  -- Add all of the seed events to our event pools uniformly.
  let seeds = networkSeeds ++ processSeeds
  let xs = [(x,y) | x <- seeds, y <- [0..31]]
  newPrng <- forM xs (\(event, poolNum) -> addRandomEvent (gState, reseedCount, pools) poolNum event)
  
  -- Run CSPRNG, reseeding as necessary.
  forever $ do
    newPrng <- forM xs (\(event, poolNum) -> 
      addRandomEvent (gState, reseedCount, pools) poolNum event)
    randomData (last newPrng) 32
