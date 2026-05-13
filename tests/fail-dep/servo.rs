//@run:1
// Note: at the moment, this test reports a false positive use-after-free.
// However, it *should* have an aliasing violation. (see https://github.com/servo/mozjs/pull/688)
// We expect this test to break CI as we continue to add additional feature support, making it
// a useful signal for our progress.
use std::ptr;
use mozjs::context::JSContext;
use mozjs::gc::{HandleObject, HandleValue};
use mozjs::jsapi::{GCReason, OnNewGlobalHookOption};
use mozjs::jsval::ObjectValue;
use mozjs::realm::AutoRealm;
use mozjs::rooted;
use mozjs::rust::wrappers2::{JS_NewGlobalObject, JS_NewPlainObject, JS_GC};
use mozjs::rust::{JSEngine, RealmOptions, Runtime, SIMPLE_GLOBAL_CLASS};

fn main() {
    let engine = JSEngine::init().unwrap();
    let mut runtime = Runtime::new(engine.handle());
    let context = runtime.cx();
    let h_option = OnNewGlobalHookOption::FireOnNewGlobalHook;
    let c_option = RealmOptions::default();

    unsafe {
        rooted!(&in(context) let global = JS_NewGlobalObject(
            context,
            &SIMPLE_GLOBAL_CLASS,
            ptr::null_mut(),
            h_option,
            &*c_option,
        ));
        let mut realm = AutoRealm::new_from_handle(context, global.handle());
        let context = &mut realm;

        rooted!(&in(context) let object = JS_NewPlainObject(context));
        rooted!(&in(context) let value = ObjectValue(object.get()));
        compare(context, object.handle(), value.handle());
    }
}

#[inline(never)]
fn compare(context: &mut JSContext, object: HandleObject<'_>, value: HandleValue<'_>) {
    let ptr = object.get();
    assert_eq!(ptr, value.get().to_object());
    unsafe { JS_GC(context, GCReason::API) };
    assert_eq!(object.get(), value.get().to_object());
    assert_ne!(ptr, object.get());
}
