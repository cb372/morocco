extern crate crypto;
extern crate rand;

use self::crypto::{ symmetriccipher, buffer, aes, blockmodes };
use self::crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };

//use self::rand::{ Rng, OsRng };

// Based on (i.e. copy-pasted from) 
// https://github.com/DaGenix/rust-crypto/blob/master/examples/symmetriccipher.rs

// Decrypts a buffer with the given key and iv using AES-256/CBC/Pkcs encryption
pub fn decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut decryptor = aes::cbc_decryptor(
            aes::KeySize::KeySize256,
            key,
            iv,
            blockmodes::PkcsPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = try!(decryptor.decrypt(&mut read_buffer, &mut write_buffer, true));
        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }

    Ok(final_result)
}
