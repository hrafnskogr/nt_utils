use std::char::{decode_utf16, REPLACEMENT_CHARACTER};
use std::fmt;

#[derive(PartialEq)]
pub enum Integer
{
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    USize(usize),
}

#[macro_export]
macro_rules! read_null
{
    ($addr: expr, $size: ident) => 
    {
        {
            let mut chunks: Vec<$size> = Vec::new();
            let mut idx = 0;
            let step = std::mem::size_of::<$size>();

            loop
            {
                let chunk = unsafe { *(($addr + idx) as *const $size) };
                if chunk == 0
                {
                    break;
                }
                
                chunks.push(chunk);
                idx += step;
            }

            (chunks, idx/step)
        }
    };
}

pub unsafe fn read_mem<T:Copy>(addr: usize, size: usize, step: usize) -> MemSlice<T>
{
    let mut mem: Vec<T> = Vec::new();
    let mut idx = 0;

    while idx < size
    {
        let val = *((addr+idx) as *const T);
        mem.push(val);
        idx += step;
    }

    MemSlice{stub: mem}
}

pub unsafe fn hex_dump(addr: usize, offset: usize, size: usize)
{
    for i in 0..size
    {
        let arr: [u8;16] = *((addr + ((i * 0x10) + offset)) as *const [u8;16]);
        let mut chars: Vec<u8> = Vec::new();

        for &var in arr.iter()
        {
            match &var
            {
                33..=126 => &chars.push(var),
                _ => &chars.push(46u8),
            };
            print!("{:02x} ", &var);
        }

        println!("{}", String::from_utf8_lossy(&chars));
    }
}

pub fn utf16_to_str(utf: &[u16]) -> String
{
    decode_utf16(utf.iter().cloned())
            .map(|r| r.unwrap_or(REPLACEMENT_CHARACTER))
            .collect()
}


// Memory Structure to holds bytes
// and associated methods
pub struct MemSlice<T>
{
    pub stub: Vec<T>,
}

impl fmt::Display for MemSlice<u8> 
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result 
    {
        write!(f, "[ {}]", self.stub.iter().cloned().map(|x| format!("{:02X} ",x)).collect::<String>())
    }
}

impl PartialEq for MemSlice<u8>
{
    fn eq (&self, other: &Self) -> bool
    {
        if self.stub.len() != other.stub.len()
        {
            return false
        }

        for i in 0..self.stub.len()
        {
            if &self.stub[i] != &other.stub[i]
            {
                return false
            }
        }

        true
    }
}

impl Eq for MemSlice<u8> {}
