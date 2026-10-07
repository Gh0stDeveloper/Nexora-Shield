use crate::ir::VmException;
use crate::value::VmValue;

pub trait VmHost {
    fn load_field(
        &mut self,
        object: Option<&VmValue>,
        field: u32,
    ) -> std::result::Result<VmValue, VmException>;

    fn store_field(
        &mut self,
        object: Option<&VmValue>,
        field: u32,
        value: &VmValue,
    ) -> std::result::Result<(), VmException>;

    fn call(&mut self, method: u32, args: &[VmValue]) -> std::result::Result<VmValue, VmException>;

    fn exception_type(&self, _value: &VmValue) -> Option<String> {
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
    ) -> std::result::Result<VmValue, VmException> {
        Err(host_exception(&format!(
            "field read #{field} is unavailable"
        )))
    }

    fn store_field(
        &mut self,
        _object: Option<&VmValue>,
        field: u32,
        _value: &VmValue,
    ) -> std::result::Result<(), VmException> {
        Err(host_exception(&format!(
            "field write #{field} is unavailable"
        )))
    }

    fn call(
        &mut self,
        method: u32,
        _args: &[VmValue],
    ) -> std::result::Result<VmValue, VmException> {
        Err(host_exception(&format!(
            "method call #{method} is unavailable"
        )))
    }
}

fn host_exception(message: &str) -> VmException {
    VmException {
        type_name: Some("Ldev/nexora/shield/VmHostException;".to_owned()),
        value: VmValue::Const(hash_message(message)),
    }
}

fn hash_message(message: &str) -> u16 {
    message.bytes().fold(0_u16, |state, byte| {
        state.wrapping_mul(31).wrapping_add(u16::from(byte))
    })
}
