////! Buffer for program and data.
////! ## Authors
////!
////! The Veracruz Development Team.
////!
////! ## Licensing and copyright notice
////!
////! See the `LICENSE.markdown` file in the Veracruz root directory for
////! information on licensing and copyright.

//use err_derive::Error;
//use std::{collections::HashMap, result::Result, vec::Vec};

//type ClientID = u64;
//type PackageID = u64;
//type DataPackage = execution_engine::hcall::common::DataSourceMetadata;


    ///// Add the data package into `buffer` and return true if it does not exist, otherwise false.
    //fn buffer_package(
        //buffer: &mut HashMap<ClientID, HashMap<PackageID, DataPackage>>,
        //package: &DataPackage,
    //) -> bool {
        //let client_id = package.get_client_id();
        //let package_id = package.get_package_id();
        //if !buffer.contains_key(&client_id) {
            //buffer.insert(client_id, HashMap::new());
        //}
        //buffer
            //.get_mut(&client_id)
            //.map(|l| {
                //if l.contains_key(&package_id) {
                    //// a package exists
                    //false
                //} else {
                    //l.insert(package_id, package.clone());
                    //true
                //}
            //})
            //// default is false in case, that is, `failure` state.
            //.unwrap_or(false)
    //}


    ///// Fetch the buffered package. If the package does not exist, return None.
    //fn get_package(
        //buffer: &HashMap<ClientID, HashMap<PackageID, DataPackage>>,
        //client_id: ClientID,
        //package_id: PackageID,
    //) -> Option<&DataPackage> {
        //buffer.get(&client_id).map(|l| l.get(&package_id)).flatten()
    //}
//}
