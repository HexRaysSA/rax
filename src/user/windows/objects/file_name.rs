use super::{ObjId, Objects};
use crate::user::windows::fs::FileNameOrigin;

impl Objects {
    pub(crate) fn set_file_name_origin(
        &mut self,
        id: ObjId,
        origin: Result<FileNameOrigin, String>,
    ) {
        let entry = self.objs.get_mut(&id).expect("new file object");
        entry.file_name_origin = Some(origin.map(|origin| {
            if let super::Object::File(file) = &entry.obj
                && let Some(retained) = &file.host
            {
                return origin.bind(retained, &file.host_path);
            }
            origin
        }));
    }

    pub(crate) fn file_name_origin(&self, handle: u64) -> Option<&Result<FileNameOrigin, String>> {
        self.objs.get(&self.id(handle)?)?.file_name_origin.as_ref()
    }
}
