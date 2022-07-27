#![feature(proc_macro_diagnostic)]

use proc_macro::{Diagnostic, Level, TokenStream};
use proc_macro2::{Ident, Span};
use quote::quote;
use syn::{punctuated::Punctuated, token::Colon2, ItemFn, Path, PathSegment};

fn error(span: Span, message: &str) -> TokenStream {
    Diagnostic::spanned(span.unwrap(), Level::Error, message).emit();
    TokenStream::new()
}

fn make_path(abs: bool, segs: &[&str]) -> Path {
    Path {
        leading_colon: if abs { Some(Colon2::default()) } else { None },
        segments: Punctuated::from_iter(segs.iter().map(|s| PathSegment {
            ident: Ident::new(s, Span::call_site()),
            arguments: syn::PathArguments::None,
        })),
    }
}

#[cfg(feature = "pc")]
static EMBASSY_EXECUTOR_PATH: &[&str] = &["pal", "embassy", "executor"];
#[cfg(feature = "nrf52840")]
static EMBASSY_EXECUTOR_PATH: &[&str] = &["pal", "embassy_nrf", "executor"];

#[proc_macro_attribute]
pub fn main(_attr: TokenStream, input: TokenStream) -> proc_macro::TokenStream {
    let mut f = syn::parse_macro_input!(input as ItemFn);
    if f.sig.asyncness.is_none() {
        return error(Span::call_site(), "function must be async");
    }

    f.sig.ident = Ident::new("__app_main", Span::call_site());

    let init_path = make_path(true, &["pal", "init"]);
    let embassy_path = make_path(true, &["pal", "embassy"]);
    let executor_path = make_path(true, EMBASSY_EXECUTOR_PATH);

    let real_main = &f.sig.ident;
    let wrapper = Ident::new(&format!("{}_wrapper", real_main), Span::call_site());

    quote! {
        #f

        #[doc(hidden)]
        fn #wrapper(spawner: #executor_path::Spawner) -> #executor_path::SpawnToken<impl Sized> {
            use #embassy_path::executor::raw::TaskPool;

            #init_path(spawner);

            type Fut = impl ::core::future::Future + 'static;
            static POOL: TaskPool<Fut, 1usize> = TaskPool::new();
            POOL.spawn(move || {
                async move {
                    #real_main().await;
                    panic!("main returned");
                }
            })
        }

        #[no_mangle]
        fn main() {
            use #executor_path::Executor;
            use #embassy_path::util::Forever;

            static EXECUTOR: Forever<Executor> = Forever::new();
            let executor = EXECUTOR.put(Executor::new());
            executor.run(|spawner| spawner.must_spawn(#wrapper(spawner)));
        }
    }
    .into()
}
