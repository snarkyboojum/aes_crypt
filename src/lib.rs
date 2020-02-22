// AES works with a constant block size of 128 bits
pub const BLOCK_SIZE: usize = 16;

// supported key lengths
#[derive(Copy, Clone)]
pub enum KeyLength {
    OneTwentyEight = 128,
    OneNinetyTwo = 192,
    TwoFiftySix = 256,
}

// number of rounds will depend on keylength
pub enum Rounds {
    Ten = 10,      // for key length of 128 bits
    Twelve = 12,   // for key length of 192 bits
    Fourteen = 14, // for key length of 256 bits
}

// Use a static Rijndael S-box (substitution box / lookup table)
// see p19 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
const S_BOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

// see p22 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
const INV_S_BOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

// "mix in" key material with state
// xor each column of state with 128 bits of the key material
fn add_round_key(state: &mut [u8; 16], key: &[u32]) {
    let column_xor = &mut [0u8; 4];

    // get each column in the existing state matrix
    for column_index in 0..4 {
        let column = get_column(column_index, state);
        //println!("Column is: {:?}", column);

        // xor the column with the key (key is 4 bytes)
        let column_field = as_u32_be(column) ^ key[column_index];
        as_u8_array(column_field, column_xor);
        //println!("XOR'd column is: {:?}", column_xor);

        // build a new state matrix by column from column_xor
        let mut c_index = column_index;
        for item in column_xor.iter() {
            state[c_index] = *item;
            c_index += 4;
        }
    }
}

// split each byte into low and high nibbles and use that to index into the S_BOX
// to substitute the byte
// the high nibble is used as a row index
// the low nibble is ujsed as the column index
// e.g. for 0x73, we look at row 7 and column 3 to look up the substitute byte
fn sub_bytes(state: &mut [u8; 16], s_box: &[u8; 256]) {
    // get the low and high nibble of each byte and look up in S_BOX
    for byte in state.iter_mut() {
        let low_nibble = *byte & 0xf;
        let high_nibble = (*byte >> 4) & 0xf as u8;

        // we use the high_nibble as a "row" index into S_BOX and the low_nibble as a "column" index
        let new_byte_index = (high_nibble as usize) * 16 + low_nibble as usize; // S_BOX is index from 0

        //println!("Index into S_BOX: {}", new_byte_index);
        let new_byte: u8 = s_box[new_byte_index];
        //println!("Subbed byte is: {:#02x}", new_byte);

        *byte = new_byte;
    }
}

fn shift_bytes(bytes: &mut [u8; 4]) {
    let a = bytes[0];
    let b = bytes[1];
    let c = bytes[2];
    let d = bytes[3];
    bytes[0] = b;
    bytes[1] = c;
    bytes[2] = d;
    bytes[3] = a;
}

// get a specific column from a 4x4 matrix, indexed by column_index
fn get_column(column_index: usize, matrix: &[u8]) -> [u8; 4] {
    //println!("Getting column: {}", column_index);
    //println!("State is: {:?}", matrix);

    let mut item_index = column_index;
    let mut column = [0u8; 4];
    let mut i = 0;
    while item_index < 16 {
        //println!("{}", item_index);
        column[i] = matrix[item_index];
        item_index += 4;
        i += 1;
    }

    //println!("Column is: {:2x?}", column);
    column
}

// multiplication of val by x (where x is part of GF(2^8))
// this is also called 'xtime' in other literature
//   #define xtime(x)   ((x<<1) ^ (((x>>7) & 1) * 0x11b))
//fn mult_by_x(x: u8, mut val: u8) -> u8 {
fn mult_by_x(mut a: u8, mut b: u8) -> u8 {
    let mut p: u8 = 0;

    for _counter in 0..8 {
        if (b & 1) != 0 {
            p ^= a;
        }

        let hi_bit_set: bool = (a & 0x80) != 0;
        a <<= 1;
        if hi_bit_set {
            a ^= 0x1B; /* x^8 + x^4 + x^3 + x + 1 */
        }
        b >>= 1;
    }

    p
}

// mix_columns is a transformation that operates on the state matrix column-wise
// and can be written as a matrix multiplication like:
// [02 03 01 01  [s0
//  01 02 03 01   s1
//  01 01 02 03   s2
//  03 01 01 02]  s3]
const MIX_COLS_MATRIX: [u8; 16] = [
    0x2, 0x3, 0x1, 0x1, 0x1, 0x2, 0x3, 0x1, 0x1, 0x1, 0x2, 0x3, 0x3, 0x1, 0x1, 0x2,
];

const INV_MIX_COLS_MATRIX: [u8; 16] = [
    0xe, 0xb, 0xd, 0x9, 0x9, 0xe, 0xb, 0xd, 0xd, 0x9, 0xe, 0xb, 0xb, 0xd, 0x9, 0xe,
];

fn mix_columns(state: &mut [u8; 16], matrix: &[u8; 16]) -> [u8; 16] {
    let mut new_state = [0u8; 16]; // get each column in the existing state matrix
    for column_index in 0..4 {
        let column = get_column(column_index, state);
        // matrix multip_COLS_MATRIX by vector "column"
        for (i, m_row) in matrix.chunks(4).enumerate() {
            for (j, m) in m_row.iter().enumerate() {
                // XOR the items together for this item in the state matrix
                new_state[column_index + i * 4] ^= mult_by_x(*m, column[j]);
            }
        }
    }

    new_state
}

fn print_state(state: &[u8]) {
    for line in state.chunks(4) {
        println!("{:2x?} ", line);
    }
}

fn transpose_state(state: &[u8]) -> [u8; 16] {
    let mut transposed_state = [0u8; 16];
    for (i, _) in state.chunks(4).enumerate() {
        let column = get_column(i, state);
        for (j, item) in column.iter().enumerate() {
            transposed_state[i * 4 + j] = *item;
        }
    }

    transposed_state
}

// input is 16 byte, output is 16 bytes and key_schedule should be something
// like the number of rounds * keylength
pub fn cipher(input: &[u8], key_schedule: &[u32]) -> [u8; 16] {
    //println!("Length of input: {}", input.len());

    let mut state = transpose_state(input);
    //println!("Length of output: {}", state.len());
    //println!("Length of key_schedule: {}", key_schedule.len());

    assert_eq!(input.len(), 16);
    assert_eq!(state.len(), 16);
    assert_eq!(key_schedule.len(), 44); // Nr + 1

    //println!("Input");
    //print_state(&state);
    add_round_key(&mut state, &key_schedule[0..4]);

    for round in 1..Rounds::Ten as usize {
        //println!("Start of round: {}", round);
        //print_state(&state);

        sub_bytes(&mut state, &S_BOX);
        //println!("After sub_bytes()");
        //print_state(&state);

        state = shift_rows(&mut state, ShiftDirection::Left);
        //println!("After shift_rows()");
        //print_state(&state);

        state = mix_columns(&mut state, &MIX_COLS_MATRIX);
        //println!("After mix_columns()");
        //print_state(&state);

        //println!("Range for key schedule: {}, {}", round * 4, (round + 1) * 4);
        add_round_key(&mut state, &key_schedule[round * 4..(round + 1) * 4]);
    }
    //println!("Last round (without mix_columns)");
    sub_bytes(&mut state, &S_BOX);
    //println!("After sub_bytes()");
    //print_state(&state);

    state = shift_rows(&mut state, ShiftDirection::Left);
    //println!("After shift_rows()");
    //print_state(&state);

    add_round_key(
        &mut state,
        &key_schedule[(Rounds::Ten as usize * 4)..((Rounds::Ten as usize + 1) * 4)],
    );

    //println!("Output");
    //print_state(&state);
    transpose_state(&state)
}

pub fn inverse_cipher(input: &[u8], key_schedule: &[u32]) -> [u8; 16] {
    let mut state = transpose_state(input);

    assert_eq!(input.len(), 16);
    assert_eq!(state.len(), 16);
    assert_eq!(key_schedule.len(), 44); // Nr + 1

    add_round_key(
        &mut state,
        &key_schedule[Rounds::Ten as usize * 4..(Rounds::Ten as usize + 1) * 4],
    );

    for round in (1..Rounds::Ten as usize).rev() {
        state = shift_rows(&mut state, ShiftDirection::Right);
        sub_bytes(&mut state, &INV_S_BOX);
        add_round_key(&mut state, &key_schedule[round * 4..(round + 1) * 4]);
        state = mix_columns(&mut state, &INV_MIX_COLS_MATRIX);
    }
    state = shift_rows(&mut state, ShiftDirection::Right);
    sub_bytes(&mut state, &INV_S_BOX);
    add_round_key(&mut state, &key_schedule[0..4]);

    transpose_state(&state)
}

enum ShiftDirection {
    Left,
    Right,
}

// shift each row in state in the ShiftDirection by n positions depending on row number
// i.e. shift 0th row by 0, 1st row by 1, 2nd row by 2 and 3rd row by 3
fn shift_rows(state: &mut [u8; 16], dir: ShiftDirection) -> [u8; 16] {
    let mut shifted_state = [0u8; 16];

    for (i, row) in state.chunks(4).enumerate() {
        let row_len = row.len();
        for (j, item) in row.iter().enumerate() {
            match dir {
                ShiftDirection::Left => {
                    let shifted_j = (j + row_len - i) % row_len;
                    shifted_state[i * 4 + shifted_j as usize] = *item;
                }
                ShiftDirection::Right => {
                    let shifted_j = (j + row_len + i) % row_len;
                    shifted_state[i * 4 + shifted_j as usize] = *item;
                }
            }
        }
    }
    shifted_state
}

// As per FIPS 197 specification, the key schedule generates a total of
// Nb * (Nr + 1) 4-byte words, which looks like a linear array of 4 byte words
// like 0 <= i < Nb(Nr + 1) - initial algo needs 4-bytes and every round after that the same
//
// Initial input is 4, 6 or 8 4-byte words (128, 192 or 256bit keys),
// and each round needs Nb (4 byte) words of data (remembering, Nb = 4 byte words),
// so for Nr rounds, you need Nb * Nr + 1 bytes to pull Nb keys from
// e.g. you will need 11 * 4 32 bit words for 10 rounds / 128 bit AES, i.e. 176 bytes = 11 * 4 * 4 bytes
//
// see p19-20 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
//

// this will work for 10 rounds (128 bit keys)
const R_CON: [u32; 10] = [
    0x0100_0000,
    0x0200_0000,
    0x0400_0000,
    0x0800_0000,
    0x1000_0000,
    0x2000_0000,
    0x4000_0000,
    0x8000_0000,
    0x1b00_0000,
    0x3600_0000,
];

pub fn expand_key(key: &[u8], expanded_key: &mut [u32], key_length: KeyLength) {
    const NB: usize = 4;
    let n_k = key_length as usize / 32;
    let key_bytes = key_length as usize / 8;

    assert_eq!(key_bytes, key.len());
    assert_eq!(key.len(), 16); // only support 128 bit keys right now

    // for 128 bit keys, each of the 10 rounds will use 16 bytes from the expanded key
    // so we need to expand the key to (10 + 1) * 4 (32 bit words)
    for i in 0..n_k {
        expanded_key[i] = as_u32_be([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }
    //println!("Expanded key: {:?}", expanded_key);

    for i in n_k..NB * (Rounds::Ten as usize + 1) {
        let mut temp = expanded_key[i - 1];

        // key length is 128 or 196 bits
        if i % n_k == 0 {
            //println!("temp: {:#08x}", temp);

            let rot_word = rot_word(temp);
            let sub_word = sub_word(rot_word);
            let r_con = R_CON[(i / n_k) - 1];
            temp = sub_word ^ r_con;

            //println!("After rot_word(): {:#08x}", rot_word);
            //println!("After sub_word(): {:#08x}", sub_word);
            //println!("Rcon[i/Nk]: {:#08x}", r_con);
            //println!("After XOR with Rcon: {:#08x}", temp);
        }

        let key_index = expanded_key[i - n_k];
        expanded_key[i] = key_index ^ temp;
        //println!("w[i-Nk]: {:#08x}", key_index);
        //println!("w[i] = temp XOR w[i-Nk]: {:#08x}", expanded_key[i]);

        //println!("Expanded key: {:?}", expanded_key);
    }
}

// TODO: should be refactored - this is already implemented above
fn sub_word(word: u32) -> u32 {
    let mut bytes = [0u8; 4];
    as_u8_array(word, &mut bytes);

    // get the low and high nibble of each byte and look up in S_BOX
    for byte in bytes.iter_mut() {
        let low_nibble = *byte & 0xf;
        let high_nibble = (*byte >> 4) & 0xf as u8;
        let new_byte_index = (high_nibble as usize) * 16 + low_nibble as usize; // S_BOX is index from 0
        let new_byte: u8 = S_BOX[new_byte_index];
        //println!("Subbed byte is: {:#02x}", new_byte);
        *byte = new_byte;
    }

    //println!("Finished sub_word");

    as_u32_be(bytes)
}

// TODO: should also be refactored - this is already implemented above
fn rot_word(word: u32) -> u32 {
    let mut bytes = [0u8; 4];
    as_u8_array(word, &mut bytes);
    shift_bytes(&mut bytes);
    as_u32_be(bytes)
    //println!("Finished rot_word");
}

// assume big endian
fn as_u32_be(array: [u8; 4]) -> u32 {
    //println!("as_u32_be");
    ((array[0] as u32) << 24)
        + ((array[1] as u32) << 16)
        + ((array[2] as u32) << 8)
        + (array[3] as u32)
}

// assume big endian
fn as_u8_array(field: u32, array: &mut [u8; 4]) {
    array[3] = (field & 0xff) as u8;
    array[2] = ((field >> 8) & 0xff) as u8;
    array[1] = ((field >> 16) & 0xff) as u8;
    array[0] = ((field >> 24) & 0xff) as u8;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_as_u32_be() {
        assert_eq!(0, as_u32_be([0, 0, 0, 0]));

        assert_eq!(std::u32::MAX, as_u32_be([255, 255, 255, 255]));

        assert_eq!(4500, as_u32_be([0, 0, 17, 148]));
    }

    #[test]
    fn test_as_u8_array() {
        let mut array = [0u8; 4];

        as_u8_array(0, &mut array);
        assert_eq!(array, [0, 0, 0, 0]);

        as_u8_array(std::u32::MAX, &mut array);
        assert_eq!(array, [255, 255, 255, 255]);

        as_u8_array(4500, &mut array);
        assert_eq!(array, [0, 0, 17, 148]);
    }

    #[test]
    fn test_as_array_as_u32() {
        let array = [32, 56, 0, 254];
        let mut target = [0u8; 4];
        as_u8_array(as_u32_be(array), &mut target);
        assert_eq!(target, array);
    }
    #[test]
    fn test_as_u32_as_array() {
        let mut target = [0u8; 4];
        let val = 5678;
        as_u8_array(val, &mut target);
        assert_eq!(as_u32_be(target), val);
    }

    #[test]
    fn test_rot_word() {
        assert_eq!(
            rot_word(as_u32_be([0, 0, 17, 148])),
            as_u32_be([0, 17, 148, 0])
        );

        assert_eq!(
            rot_word(as_u32_be([0xf3, 0x01, 0x00, 0x00])),
            as_u32_be([0x01, 0x00, 0x00, 0xf3])
        );
    }

    // from FIPS standard, see p27 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
    #[test]
    fn test_expand_key() {
        println!("Output from test_expand_key()");
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];

        let expanded_key_correct: [u32; 40] = [
            0xa0fa_fe17,
            0x885_42cb1,
            0x23a3_3939,
            0x2a6c_7605,
            0xf2c2_95f2,
            0x7a96_b943,
            0x5935_807a,
            0x7359_f67f,
            0x3d80_477d,
            0x4716_fe3e,
            0x1e23_7e44,
            0x6d7a_883b,
            0xef44_a541,
            0xa852_5b7f,
            0xb671_253b,
            0xdb0b_ad00,
            0xd4d1_c6f8,
            0x7c83_9d87,
            0xcaf2_b8bc,
            0x11f9_15bc,
            0x6d88_a37a,
            0x110b_3efd,
            0xdbf9_8641,
            0xca00_93fd,
            0x4e54_f70e,
            0x5f5f_c9f3,
            0x84a6_4fb2,
            0x4ea6_dc4f,
            0xead2_7321,
            0xb58d_bad2,
            0x312b_f560,
            0x7f8d_292f,
            0xac77_66f3,
            0x19fa_dc21,
            0x28d1_2941,
            0x575c_006e,
            0xd014_f9a8,
            0xc9ee_2589,
            0xe13f_0cc8,
            0xb663_0ca6,
        ];

        // TODO: should get get/check 40 bytes or 44 bytes of expanded key?
        let mut expanded_key: [u32; 44] = [0u32; 44];
        expand_key(&key, &mut expanded_key, KeyLength::OneTwentyEight);

        for (i, elem) in expanded_key[4..].iter().enumerate() {
            println!("Testing elem: {}, {:#08x?}", i, elem);
            assert_eq!(*elem, expanded_key_correct[i]);
        }
    }

    #[test]
    fn test_cipher() {
        println!("Output from test_expand_key()");
        let plaintext: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let output_correct: [u8; 16] = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
            0xc5, 0x5a,
        ];

        // do expand key
        let expanded_key = &mut [0u32; 44];
        expand_key(&key, expanded_key, KeyLength::OneTwentyEight);

        // run cipher
        let output: [u8; 16] = cipher(&plaintext, expanded_key);

        println!("Testing: {:#02x?}", output);
        println!("against: {:#02x?}", output_correct);
        assert_eq!(output.len(), output_correct.len());

        for (i, elem) in output.iter().enumerate() {
            println!("Testing elem: {}, {:#02x?}", i, elem);
            assert_eq!(*elem, output_correct[i]);
        }
    }

    #[test]
    fn test_inverse_shift_rows() {
        let mut state = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let state_correct = [0u8, 1, 2, 3, 7, 4, 5, 6, 10, 11, 8, 9, 13, 14, 15, 12];

        let shifted_state = shift_rows(&mut state, ShiftDirection::Right);
        for (i, &item) in state_correct.iter().enumerate() {
            assert_eq!(item, shifted_state[i]);
        }
    }

    #[test]
    fn test_inverse_cipher() {
        println!("Output from test_expand_key()");
        let cipher_text: [u8; 16] = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
            0xc5, 0x5a,
        ];
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let output_correct: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];

        let expanded_key = &mut [0u32; 44];
        expand_key(&key, expanded_key, KeyLength::OneTwentyEight);

        // run inverse cipher
        let output: [u8; 16] = inverse_cipher(&cipher_text, expanded_key);

        println!("Testing: {:#02x?}", output);
        println!("against: {:#02x?}", output_correct);
        assert_eq!(output.len(), output_correct.len());

        for (i, elem) in output.iter().enumerate() {
            println!("Testing elem: {}, {:#02x?}", i, elem);
            assert_eq!(*elem, output_correct[i]);
        }
    }
}
