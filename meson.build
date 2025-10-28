project(
    'postgres-keycloak-oauth-validator', 'c',
    license: 'Apache-2.0',
    license_files: 'LICENSE',
    version: '0.0.1')

# pg_config command is required to get the include directory for
# the headers
pg_config = find_program('pg_config')
includedir_server = run_command(pg_config, '--includedir-server', check: true).stdout().strip()

# PostgreSQL required for standard build (this may not be needed)
postgres = dependency('libpq')
# libcurl is required for the oauth calls
libcurl = dependency('libcurl')

# The library is built as a shared object since it's going to be
# loaded into PostgreSQL later as an extension.
# Setting the prefix to '' helps to not habe a `lib` prefix on the
# final file created
shared_module('kc_validator', 'src/kc_validator.c',
              dependencies: [postgres, libcurl],
              include_directories: [includedir_server],
              name_prefix: '')
