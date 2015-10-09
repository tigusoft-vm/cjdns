
// C implementation code to be included in other programs to avoid copy-pasting
// Don't want to complicate this situation with multi-file builds so just let's #includet his code here
// directly into our test program

void test_libuv_version() {
    printf("This program uses libuv: compiled with headers: %d.%d.%d%s %s and linked with library: %s \n",
        UV_VERSION_MAJOR, UV_VERSION_MINOR, UV_VERSION_PATCH, UV_VERSION_SUFFIX,
        ( UV_VERSION_IS_RELEASE ? "(release)" : "(test version)" ),
        uv_version_string()
        );

		{
			long int version_compiled = UV_VERSION_HEX;
			long int version_linked = uv_version();
			if ( UV_VERSION_HEX != uv_version()) {
				printf("WARNING: this program was compiled with one version of libuv (hex=%lu) and linked with another (hex=%lu)" 
					"this is probably a problem!\n", 
					version_compiled, version_linked
				);
			} 
			else printf("Ok, compiled and linked version numbers seem to match (%lu) and (%lu) (though we check only numbers, not the suffix extra version)\n", version_compiled, version_linked);
		}
}


