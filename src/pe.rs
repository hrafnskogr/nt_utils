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
    optional_header_offset: u32,
    export_directory_offset: u32,
    export_directory_addr: usize,
    exp_dir_base: usize,
    fnames: Vec<String>,
    fnames_ordinals: Vec<usize>,
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
                               optional_header_offset: 0,
                               export_directory_offset: 0,
                               export_directory_addr: 0,
                               exp_dir_base: 0,
                               fnames: Vec::new(),
                               fnames_ordinals: Vec::new(),
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

        // Ordinal Base:
        self.exp_dir_base = *((self.export_directory_addr + 0x10) as *const u8) as usize;

        // Populate the array of function names
        for idx in 0..self.number_of_names()
        {
            self.fnames.push(self.fname_from_index(idx as usize)); 
        }

        // Populate the array of ordinals
        
        for idx in 0..self.number_of_names()
        {
            self.fnames_ordinals.push(self.ford_from_index(idx as usize) + self.exp_dir_base);
        }

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

    pub fn syscall_from_name(&self, fname: &str) -> usize
    {
        let idx = self.idx_from_name(fname);
        if idx < 0
        {
            panic!("Can't find index for {}", fname);
        }

        let idx = idx as usize;

        let ord = self.fnames_ordinals[idx];
        let faddr = self.faddr_from_ord(ord);

        unsafe
        {
            crate::memory::read_mem::<u8>(faddr + 4, 1, 1).stub[0] as usize
        }
    }

    pub fn fname_from_index(&self, index: usize) -> String
    {
        let name_addr: usize;

        unsafe
        {
            name_addr = self.base_addr
                        + *((self.base_addr + self.names_offset() 
                        + (index * 4)) as *const u32) as usize;
        }

        let (name, _) = read_null!(name_addr as usize, u8);
        let name = String::from_utf8_lossy(&name).to_string(); //.unwrap();

        name
    }

    pub fn ford_from_index(&self, index: usize) -> usize
    {
        let size = 2;
        let ret: usize;

        unsafe
        {
            let ord_addr = self.base_addr + self.ordinals_offset(); 
            let ord = crate::memory::read_mem::<u8>(ord_addr + size * index, size, 1);
            ret = u16::from_le_bytes(ord.stub.try_into().expect("failed conversion")) as usize; 
        }

        ret
    }
    
    pub fn faddr_from_ord(&self, ord: usize) -> usize
    {
            let rva = self.rva_from_ord(ord);

            (self.base_addr + rva) as usize
    }

    // TODO: handle proper error instead of -1
    pub fn idx_from_name(&self, fname: &str) -> isize
    {
        let mut idx: isize = 0;

        for name in &self.fnames
        {
            if name == fname
            {
                return idx;
            }

            idx += 1;
        }

        -1
    }

    pub fn rva_from_ord(&self, ord: usize) -> usize
    {
        unsafe
        {
            *((self.base_addr 
               + self.funcs_offset() 
               + ((ord - self.exp_dir_base) * 4)) 
               as *const u32) as usize
        }
    }

    pub unsafe fn funcs_addr(&self) -> usize
    {
        self.base_addr +  self.funcs_offset() as usize
    }

    // TODO: Rewrite
    pub unsafe fn find_func_addr(&self, find: &str) -> (usize, usize)
    {
        let mut ord = 1;

        // Compute ordinal for given function
        for _ in 0..(self.number_of_names())
        {
            let name = self.fname_from_index(ord);
            
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
    type Item = (usize, usize);
    type IntoIter = PEImageIntoIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        PEImageIntoIterator {
            pe: self,
            ord_idx: 0,
        }
    }
}

pub struct PEImageIntoIterator<'a>
{
    pe: &'a PEImage,
    ord_idx: usize,
}

impl<'a> Iterator for PEImageIntoIterator<'a>
{
    type Item = (usize, usize);

    fn next(&mut self) -> Option<Self::Item> 
    {
        if self.ord_idx == (self.pe.fnames_ordinals.len())
        {
            return None
        }

        let ord = self.ord_idx;

        self.ord_idx += 1;

        Some((self.pe.fnames_ordinals[ord], ord))
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
