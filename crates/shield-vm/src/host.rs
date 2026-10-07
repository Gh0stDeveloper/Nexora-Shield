use crate::constant_pool::ConstantPool;
use crate::ir::VmException;
use crate::value::VmValue;

pub trait VmHost {
    fn load_field(
        &mut self,
        object: Option<&VmValue>,
        field: u32,
        constants: &ConstantPool,
    ) -> std::result::Result<VmValue, VmException>;

    fn store_field(
        &mut self,
        object: Option<&VmValue>,
        field: u32,
        value: &VmValue,
        constants: &ConstantPool,
    ) -> std::result::Result<(), VmException>;

    fn call(
        &mut self,
        method: u32,
        args: &[VmValue],
        constants: &ConstantPool,
    ) -> std::result::Result<VmValue, VmException>;

    fn exception_type(&self, _value: &VmValue, _constants: &ConstantPool) -> Option<String> {
        None
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct NullHost;

impl VmHost for NullHost {
    fn load_field(
        &mut self,
        _object: Option<&VmValue>,
        field: u32,
        _constants: &ConstantPool,
    ) -> std::result::Result<VmValue, VmException> {
        Err(host_exception())
    }

    fn store_field(
        &mut self,
        _object: Option<&VmValue>,
        _field: u32,
        _value: &VmValue,
        _constants: &ConstantPool,
    ) -> std::result::Result<(), VmException> {
        Err(host_exception())
    }

    fn call(
        &mut self,
        _method: u32,
        _args: &[VmValue],
        _constants: &ConstantPool,
    ) -> std::result::Result<VmValue, VmException> {
        Err(host_exception())
    }
}

fn host_exception() -> VmException {
    VmException {
        type_name: Some("Ldev/nexora/shield/VmHostException;".to_owned()),
        value: VmValue::Null,
    }
}
