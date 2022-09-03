use crate::err::*;
use std::fmt;
use std::arch::asm;

pub struct Peb
{
    pub base_addr: usize,
}

// Simple implementation
// Only ldr data is accessible right now
impl Peb
{
    pub fn new() -> Peb
    {

        let peb_addr: usize;
        unsafe
        {
            asm!("xor rax, rax",               // put rax to 0
                 "mov r8, gs:[rax + 0x60]",    // load peb addr into rbx
                out("r8") peb_addr);
        }
        Peb { base_addr: peb_addr }
    }

    pub fn get_ldr(&self) -> Ldr
    {
        unsafe 
        {
            let base_addr: usize = *((self.base_addr + 0x18) as *const usize) as usize;
            Ldr::new(base_addr)
        }
    }
}

pub struct Ldr
{
    pub in_load_order_module_list: LdrModule,
    pub in_memory_order_module_list: LdrModule,
    pub in_initialization_order_module_list: LdrModule,
}

impl Ldr
{
    pub fn new(base_addr: usize) -> Ldr
    {
        Ldr {in_load_order_module_list: LdrModule::new(base_addr + 0x10, 0),
             in_memory_order_module_list: LdrModule::new(base_addr + 0x20, 0x10),
             in_initialization_order_module_list: LdrModule::new(base_addr + 0x30, 0x20) }
    }
}


pub struct LdrModule
{
    list_header: usize,      // Address of the list header
    modules:     Vec<Module>, // List of addresses of each entry
    base_addr:   usize,      // Address the current entry
    flink:       usize,      // Current address pointed by the flink ptr
    blink:       usize,      // Current address pointed by the blink ptr
    offset:      usize,      // Offset of the ListEntry position inside the containing structure
}

// TODO: Proper error handling
// Currently only returning Oks
impl LdrModule
{
    pub fn new(header_addr: usize, offset: usize) -> LdrModule
    {
        let mut le = LdrModule { list_header: header_addr, 
                                 modules: Vec::new(),
                                 base_addr: 0, 
                                 flink: 0, 
                                 blink: 0,
                                 offset};

        le.init();
        le
    }

    fn init(&mut self)
    {
        self.reset();

        self.modules.push(self.module().unwrap());

        while let Ok(_) = self.next()
        {
            self.modules.push(self.module().unwrap());
        }

        self.reset();
    }

    pub fn reset(&mut self)
    {
        unsafe
        {
            self.base_addr = *(self.list_header as *const usize) as usize;
            self.flink = *(self.base_addr as *const usize) as usize;
            self.blink = *((self.base_addr + 0x8) as *const usize) as usize;
        }
    }
        
    pub fn next(&mut self) -> Result<(), PEErr>
    {
        if self.flink == self.list_header
        {
            return Err(PEErr {
                        status: ErrState::Failure,
                        message: String::from("Error, cannot reach the next 
                                                list entry: end of list reached.")} );
        }

        self.base_addr = self.flink;
        unsafe
        {
            self.flink = *(self.base_addr as *const usize) as usize;
            self.blink = *((self.base_addr + 0x8) as *const usize) as usize;
        }

        Ok(())
    }
    
    pub fn module(&self) -> Result<Module, PEErr>
    {
        LdrModule::get_module(self.base_addr, self.offset)
    }

    pub fn find_module(&self, mod_name: &str) -> Result<Module, PEErr>
    {
        for m in &self.modules
        {
            if m.name == mod_name
            {
                return Ok(m.clone())
            }
        }

        Err( PEErr 
             { 
                status: ErrState::Failure, 
                message: String::from("nope") 
             } )

        /*
        match self.modules.iter().next().filter(|&m| {println!("pipo"); &m.name == mod_name})
        {
            Some(x) => return Ok(x.clone()),
            None => return Err( PEErr { status: ErrState::Failure, message: String::from("nope") } ),
        }
        */
        
        //self.modules.iter().filter(|&m| m.name == mod_name).collect::<Module>() 
    }

    fn get_module(addr: usize, offset: usize) -> Result<Module, PEErr>
    {
        Ok( Module 
            {
                name:           LdrModule::get_module_name(addr, offset).unwrap(),
                full_name:      LdrModule::get_module_full_name(addr, offset).unwrap(),
                dll_base:       LdrModule::get_module_dll_base(addr, offset),
                entry_point:    LdrModule::get_module_entry_point(addr, offset),
                size_of_image:  LdrModule::get_module_size_of_image(addr, offset),
            })
    }

    pub fn get_name(&self) -> Result<String, PEErr>
    {
        LdrModule::get_module_name(self.base_addr, self.offset)
    }

    pub fn get_full_name(&self) -> Result<String, PEErr>
    {
        LdrModule::get_module_full_name(self.base_addr, self.offset)
    }

    pub fn get_dll_base(&self) -> usize
    {
        LdrModule::get_module_dll_base(self.base_addr, self.offset)
    }

    pub fn get_entry_point(&self) -> usize
    {
        LdrModule::get_module_entry_point(self.base_addr, self.offset)
    }

    pub fn get_size_of_image(&self) -> usize
    {
        LdrModule::get_module_size_of_image(self.base_addr, self.offset)
    }

    fn get_module_name(addr: usize, offset: usize) -> Result<String, PEErr>
    {
        let name_addr: usize = LdrModule::compute_addr(addr, offset, 0x60);
        
        LdrModule::get_u16_string_at(name_addr)
    }

    fn get_module_full_name(addr: usize, offset: usize) -> Result<String, PEErr>
    {
        let name_addr: usize = LdrModule::compute_addr(addr, offset, 0x50);
        
        LdrModule::get_u16_string_at(name_addr) 
    }

    fn get_u16_string_at(addr: usize) -> Result<String, PEErr>
    {
        let bytes = read_null!(addr, u16);
        let string = crate::memory::utf16_to_str(&bytes.0[..]);

        Ok(string)
    }

    fn get_module_dll_base(addr: usize, offset: usize) -> usize
    {
        LdrModule::compute_addr(addr, offset, 0x30)
    }

    fn get_module_entry_point(addr: usize, offset: usize) -> usize
    {
        LdrModule::compute_addr(addr, offset, 0x38)
    }

    fn get_module_size_of_image(addr: usize, offset: usize) -> usize
    {
        LdrModule::compute_addr(addr, offset, 0x40)
    }

    fn compute_addr(addr: usize, ldr_offset: usize, data_offset: usize) -> usize
    {
        unsafe
        {
            *((addr + data_offset - ldr_offset) as *const usize)
        }
    }
}

impl<'a> IntoIterator for &'a LdrModule
{
    type Item = Module;
    type IntoIter = LdrModuleIterator<'a>;

    fn into_iter(self) -> Self::IntoIter
    {
        LdrModuleIterator
        {
            ldr_module: self,
            index: 0,
        }
    }
}

pub struct LdrModuleIterator<'a>
{
    ldr_module: &'a LdrModule,
    index: usize,
}

impl<'a> Iterator for LdrModuleIterator<'a>
{
    type Item = Module;

    fn next(&mut self) -> Option<Module>
    {
        if self.index < self.ldr_module.modules.len()
        {
            let ret = Some(Module
                           {
                                name:          self.ldr_module.modules[self.index].name.clone(),
                                full_name:     self.ldr_module.modules[self.index].full_name.clone(),
                                dll_base:      self.ldr_module.modules[self.index].dll_base,
                                entry_point:   self.ldr_module.modules[self.index].entry_point,
                                size_of_image: self.ldr_module.modules[self.index].size_of_image,
                           });

            self.index += 1;

            return ret
        }
        
        None
    }
}

impl fmt::Display for LdrModule 
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result 
    {
        write!(f,"[- {:#x} | {} -]\n\
                  flink: {:#x}\n\
                  blink: {:#x}",
                  self.base_addr,
                  self.get_name().unwrap(),
                  self.flink,
                  self.blink)
    }
}

#[derive(Clone, Debug)]
pub struct Module
{
    pub name: String,           // 0x60
    pub full_name: String,      // 0x50
    pub dll_base: usize,        // 0x30
    pub entry_point: usize,     // 0x38
    pub size_of_image: usize,   // 0x40
}

impl fmt::Display for Module
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        write!(f, "[- {} -]\n\
                  Path: {}\n\
                  Base: {:#x}\n\
                  EP:   {:#x}\n\
                  Size: {}\n",
                  self.name,
                  self.full_name,
                  self.dll_base,
                  self.entry_point,
                  self.size_of_image)
    }
}


