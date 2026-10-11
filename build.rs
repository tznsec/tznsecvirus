fn main() {
    #[cfg(windows)]
    {
        let mut res = winres::WindowsResource::new();
        res.set_icon("assets/tznsecvirus.ico");
        res.set("ProductName", "TZNSECVIRUS");
        res.set("FileDescription", "TZNSECVIRUS - Deep Security Scanner");
        res.set("CompanyName", "tznsec");
        res.set("LegalCopyright", "tznsec");
        if let Err(e) = res.compile() {
            eprintln!("warning: nie udalo sie osadzic ikony: {e}");
        }
    }
}