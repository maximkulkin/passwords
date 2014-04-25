module Crypto.Password where

import qualified Control.Monad.Random as Random (fromList)
import Data.List (foldl')
import Data.Map (Map)
import qualified Data.Map as Map (empty, elems, insert, lookup, toList)
import Data.Maybe (fromMaybe)
import System.Random (randomRIO)

data CharType = Lowercase
              | Uppercase
              | Digit
              | Symbol
              deriving (Eq, Show)

instance Ord CharType where
  compare Lowercase Uppercase = LT
  compare Lowercase Digit = LT
  compare Lowercase Symbol = LT
  compare Uppercase Digit = LT
  compare Uppercase Symbol = LT
  compare Digit Symbol = LT

  compare x y | x == y    = EQ
              | otherwise = GT

lowercaseChars = "abcdefghijkpqrstuvwxyz"
uppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
digitChars     = "0123456789"
symbolChars    = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"

isCharType :: CharType -> Char -> Bool
isCharType Lowercase = (`elem` lowercaseChars)
isCharType Uppercase = (`elem` uppercaseChars)
isCharType Digit     = (`elem` digitChars)
isCharType Symbol    = (`elem` symbolChars)

formatCharType :: CharType -> String
formatCharType Lowercase = "lowercase character(s)"
formatCharType Uppercase = "uppercase character(s)"
formatCharType Digit     = "digit(s)"
formatCharType Symbol    = "symbol(s)"


randomElement :: [a] -> IO a
randomElement elems = fmap (elems!!) $ randomRIO (0, (length elems - 1))

genRandom :: CharType -> IO Char
genRandom Lowercase = randomElement lowercaseChars
genRandom Uppercase = randomElement uppercaseChars
genRandom Digit     = randomElement digitChars
genRandom Symbol    = randomElement symbolChars


data PasswordFeature = Length Int
                     | Include CharType
                     | IncludeAtLeast Int CharType
                     deriving (Eq, Show)

passwordFeatureMessage :: PasswordFeature -> String
passwordFeatureMessage (Length x) = "should be at least " ++ show x ++ " character(s) long"
passwordFeatureMessage (Include t) = "should include " ++ formatCharType t
passwordFeatureMessage (IncludeAtLeast x t) = "should have at least " ++ show x ++ " " ++ formatCharType t


data PasswordGenState = PasswordGenState (Map CharType Int) Int Int

newPasswordGenState m l =
  PasswordGenState m (sum . Map.elems $ m) l


generatePassword :: [PasswordFeature] -> IO String
generatePassword features = generate (newPasswordGenState minCounts len) ""
  where generate :: PasswordGenState -> String -> IO String
        generate (PasswordGenState _ _ 0) password = return password
        generate (PasswordGenState m min left) password = do
          let weightFunc = if left > min then defaultWeights else countWeights
          charType <- Random.fromList $ map weightFunc $ Map.toList m

          let left' = left - 1
          let charTypeCount = fromMaybe 0 $ Map.lookup charType m
              newState = if (charTypeCount == 0)
                         then PasswordGenState m min left'
                         else PasswordGenState (Map.insert charType (charTypeCount-1) m) (min-1) left'

          c <- genRandom charType

          generate newState (c:password)

          where countWeights (k, v) = (k, toRational v)
                defaultWeights (k, v) = (k, defaultCharTypeWeight k)

                defaultCharTypeWeight Lowercase = 3
                defaultCharTypeWeight _ = 1

        len = case filter isLength features of
                [] -> 8
                (Length x:_) -> x

        isLength :: PasswordFeature -> Bool
        isLength (Length _) = True
        isLength _ = False

        minCounts :: Map CharType Int
        minCounts = foldl' updateCountsWithFeature Map.empty features
          where updateCountsWithFeature m (Include t) = Map.insert t 0 m
                updateCountsWithFeature m (IncludeAtLeast x t) = Map.insert t x m
                updateCountsWithFeature m _ = m


validatePassword :: [PasswordFeature] -> String -> Either PasswordFeature ()
validatePassword features password = foldl (>>) (Right ()) $ map (checkEither password) features
  where checkEither :: String -> PasswordFeature -> Either PasswordFeature ()
        checkEither s c = if check s c then Right () else Left c

        check :: String -> PasswordFeature -> Bool
        check s (Length x)  = length s >= x
        check s (Include t) = True
        check s (IncludeAtLeast x t)  = count (isCharType t) s >= x

        count :: (a -> Bool) -> [a] -> Int
        count p xs = length . filter p $ xs
