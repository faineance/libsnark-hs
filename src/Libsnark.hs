
{-# LANGUAGE ForeignFunctionInterface #-}

module Libsnark where


import Foreign.Ptr
import Foreign.C.Types


foreign import ccall unsafe "_setup" _setup
    :: IO ()

foreign import ccall unsafe "_generate_proof" _generate_proof
    :: IO ()

