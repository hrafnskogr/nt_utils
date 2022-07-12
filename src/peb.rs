use crate::err::*;
use crate::memory::*;

pub struct Peb
{
    base_addr: usize,
}

pub struct Ldr
{
    pub length: u32,
    pub initialized: bool,
    pub in_load_order_module_list: InLoadOrderModuleList,

}

pub struct InLoadOrderModuleList
{
    base_addr:  usize,      // Address of the load order module list, as stored in the ldr
    flink:      usize,      // Current address pointed by the flink ptr
    blink:      usize,      // Current address pointed by the blink ptr
    index:     usize,      // Keeps track of where we are in the list. 0 = list header
}

impl InLoadOrderModuleList
{
    pub fn new(base_addr: usize) -> InLoadOrderModuleList
    {
        let mut list = InLoadOrderModuleList { base_addr, 
                                               flink: 0x0, 
                                               blink: 0x0,
                                               index: 0 } ;
        list.init();

        list
    }

    pub fn init(&mut self)
    {
        self.flink = self.base_addr + 0x18;
        self.blink = self.flink;
        self.index = 0;
    }

    pub fn current_entry_name(&self) -> Result<String, PEErr>
    {
        if self.index == 0
        {
            return Err( PEErr { status: ErrState::Failure, message: String::from("List currently on list header") } );
        }

        let bytes = read_null!(self.base_addr + 0x60, u16);
        let image_name = crate::memory::utf16_to_str(&bytes.0[..]);

        Ok(image_name)
    }
}



