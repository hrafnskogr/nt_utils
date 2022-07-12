use crate::err::*;
use std::fmt;

/* TODO:
 * Name formatting:
 *  fn that states addr of when it is actually an offset
 * Features:
 *  provide FNs to get mem addr of a PE section, and FNs to get offset relative to base addr
 */

// =================================================== PEName Enum

#[derive(Debug, PartialEq)]
pub enum PEName
{
    Empty,
    Is(String),
}

impl fmt::Display for PEName
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result
    {
        match self
        {
            PEName::Empty => write!(f, ""),
            PEName::Is(name) => write!(f, "{}", name),
        }
    }
}

// =================================================== PEName Enum

#[derive(Debug)]
pub struct PEImage
{
    pub base_addr: usize,
    name: PEName,
    name_init: bool,
    optional_header_offset: u32,
    export_directory_offset: u32,
    export_directory_addr: usize,
}

impl PEImage
{
    pub fn new(addr: usize) -> PEImage
    {
        PEImage::from(addr, PEName::Empty)
    }

    pub fn from(base_addr: usize, name: PEName) -> PEImage
    {
        let mut pe = PEImage { base_addr,
                               name,
                               name_init: false,
                               optional_header_offset: 0,
                               export_directory_offset: 0,
                               export_directory_addr: 0,
                             };
        unsafe
        {
            pe.init();
        }

        pe
    }

    // TODO: Return a Result<(), PEErr>
    pub unsafe fn init(&mut self)
    {
        // Read the file header offset located at offset 0x3c
        // Add 0x4 to the read offset to skip the PE Signature
        let file_header: u32 = (*((self.base_addr + 0x3c) as *const u32)) + 0x4;
        
        // The offset for the optional header is at 0x14
        self.optional_header_offset = file_header + 0x14;
        
        // Compute the offset where the offset to the export directory is stored, and retrieve it
        self.export_directory_offset = *((self.base_addr
                                            + self.optional_header_offset as usize
                                            + 0x70) as *const u32);
        
        // Compute a final absolute address to the export directory
        self.export_directory_addr = self.base_addr + self.export_directory_offset as usize;

        // TODO: Replace by a match to handle the PEName::Is(x) case
        if self.export_directory_offset != 0x0 && self.name == PEName::Empty
        {
            self.name = match self.set_export_name()
            {
                Ok(name) => name,
                Err(e)  => { 
                    eprintln!("{}", e.message);
                    PEName::Empty
                }
            }
        }
    }

    pub unsafe fn get_export_directory_ptr(&self) -> *const usize
    {
        (self.base_addr + self.export_directory_offset as usize) as *const usize
    }

    // Set the name of the PE based on the exported name
    // in the export directory
    fn set_export_name(&self) -> Result<PEName, PEErr>
    {
        let name_addr: usize;
        let name: Vec<u8>;

        unsafe
        {
            let name_offset = *((self.base_addr + self.export_directory_offset as usize + 0xC) as *const u32);
            name_addr = self.base_addr + name_offset as usize;
        }

        (name, _) = read_null!(name_addr as usize, u8);
        
        match String::from_utf8(name)
        {
            Ok(name) => return Ok( PEName::Is(name) ),
            Err(_) => return Err( PEErr 
                                  { 
                                    status: ErrState::Failure, 
                                    message: String::from("Failed to decode the name from export directory (UTF8 fail)") 
                                  } ),
        }
    }

    // TODO: implement a bool to know if name is initialized or not
    pub fn get_name(&self) -> Result<String, PEErr>
    {
        if self.export_directory_offset != 0
        {
            let ret = match &self.name
            {
                PEName::Empty => String::from("Unnamed PE"),
                PEName::Is(n) => String::from(n),
            };
            return Ok(ret);
        }

        Ok(String::from("Unnamed PE"))
    }

    pub fn set_name(&mut self, new_name: &str)
    {
        self.name = PEName::Is(String::from(new_name));
    }

    pub unsafe fn number_of_func(&self) -> u32
    {
        *((self.export_directory_addr + 0x14) as *const u32) 
    }

    pub unsafe fn number_of_names(&self) -> u32
    {
        *((self.export_directory_addr + 0x18) as *const u32) 
    }

    pub unsafe fn funcs_offset(&self) -> usize
    {
        *((self.export_directory_addr + 0x1c) as *const u32) as usize
    }
    
    pub unsafe fn names_offset(&self) -> usize
    {
        *((self.export_directory_addr + 0x20) as *const u32) as usize
    }

    pub unsafe fn ordinals_offset(&self) -> usize
    {
        *((self.export_directory_addr + 0x24) as *const u32) as usize
    }

    // List the first 3 bytes of all functions
    // Quite use less right now
    pub unsafe fn list_all_func(&self)
    {
        //let mut index = 0;
        let mut ord = 1;

        for _ in 0..(self.number_of_names())
        {
            //let name_addr = self.base_addr
            //            + *((self.base_addr + self.addr_of_names() + index) as *const u32) as usize;
            //let (name, _) = read_until_null(name_addr as usize);

            let addr = *((self.base_addr + self.funcs_addr() + (ord * 4) ) as *const u32);
            println!("{:x?}", *((self.base_addr + addr as usize) as *const [u8;3]));

            ord += 1;
            //index += 4;
        }
    }

    pub fn fname_from_ord(&self, ord: usize) -> String
    {
        let name_addr: usize;

        unsafe
        {
        name_addr = self.base_addr
                        + *((self.base_addr + self.names_offset() + (ord * 4)) as *const u32) as usize;
        }
        let (name, _) = read_null!(name_addr as usize, u8);
        let name = String::from_utf8(name).unwrap();

        name
        
    }

    pub unsafe fn faddr_from_ord(&self, ord: usize) -> usize
    {
        self.base_addr + *((self.base_addr + self.funcs_offset() + (ord * 4) ) as *const u32) as usize
    }

    pub unsafe fn funcs_addr(&self) -> usize
    {
        self.base_addr +  self.funcs_offset() as usize
    }

    pub unsafe fn find_func_addr(&self, find: &str) -> (usize, usize)
    {
        let mut ord = 1;

        // Compute ordinal for given function
        for _ in 0..(self.number_of_names())
        {
            let name = self.fname_from_ord(ord);
            
            let found = String::from(name);
            let looking_for = String::from(find);

            if found == looking_for
            {
                println!("Found {}", found);
                break
            }

            ord += 1;
        }

        // Use ordinal to get the offset of function
        // And combine it with base address
        let offset = *((self.base_addr + self.funcs_offset() + (ord * 4) ) as *const u32);
        let addr: usize = offset as usize + self.base_addr;

        (addr, ord)
    }
}

/// Iterator implementation
/// Iterate through the ordinal
/// Enable easy iteration over functions / addresses....
impl<'a> IntoIterator for &'a PEImage
{
    type Item = usize;
    type IntoIter = PEImageIntoIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        PEImageIntoIterator {
            pe: self,
            current_ord: 0,
        }
    }
}

pub struct PEImageIntoIterator<'a>
{
    pe: &'a PEImage,
    current_ord: usize,
}

impl<'a> Iterator for PEImageIntoIterator<'a>
{
    type Item= usize;

    fn next(&mut self) -> Option<Self::Item> 
    {
        unsafe
        {
            if self.current_ord > (self.pe.number_of_func() as usize)
            {
                return None
            }
        }

        self.current_ord += 1;

        Some(self.current_ord - 1)
    }
}

/// Display trait implementation
impl fmt::Display for PEImage 
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result 
    {
        unsafe
        { 
            write!(f, "[- {} -]\nBase Addr: {:#x}\nFunc num: {}\nName num: {}\nOptional Header Offset: {:#x}\nExport Directory Addr: {:#x}\nExport Directory Offset: {:#x}\nFunc Offset: {:#x}\nAddr of funcs: {:#x}", self.name, self.base_addr, self.number_of_func(), self.number_of_names(), self.optional_header_offset, self.export_directory_addr, self.export_directory_offset, self.funcs_offset(), self.funcs_addr())
        }
    }
}
