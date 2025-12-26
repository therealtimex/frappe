import os
import re

import frappe
from frappe.database.db_manager import DbManager
from frappe.utils import cint

# Protected databases that cannot be dropped
PROTECTED_DATABASES = {"postgres", "template0", "template1"}


def _validate_schema_name(schema: str) -> str:
	"""Validate PostgreSQL schema name.
	
	Args:
		schema: Schema name to validate.
		
	Returns:
		Validated schema name (lowercased).
		
	Raises:
		frappe.ValidationError: If schema name is invalid.
	"""
	if not schema:
		raise frappe.ValidationError("Schema name cannot be empty")
	
	schema = schema.strip().lower()
	
	if not re.match(r'^[a-z][a-z0-9_]*$', schema):
		raise frappe.ValidationError(
			"Schema must be lowercase, start with letter, contain only [a-z0-9_]"
		)
	
	if schema in ('public', 'information_schema') or schema.startswith('pg_'):
		raise frappe.ValidationError(f"Cannot use reserved schema name: {schema}")
	
	if len(schema) > 63:
		raise frappe.ValidationError("Schema name too long (max 63 chars)")
	
	return schema


def setup_database():
	"""Set up database for Frappe site.
	
	Supports two modes:
	- Schema mode (db_schema set): Creates PostgreSQL schema within existing database.
	  No DROP/CREATE DATABASE operations. Used for Supabase compatibility.
	- Traditional mode (db_schema not set): Creates new database with DROP/CREATE.
	"""
	db_schema = frappe.conf.get("db_schema")
	
	if db_schema:
		# Schema mode: create schema within existing database
		_setup_schema_mode(db_schema)
	else:
		# Traditional mode: create separate database
		_setup_database_traditional()


def _setup_schema_mode(schema_name: str):
	"""Create schema within existing database (mirrors traditional mode pattern).
	
	This mode:
	- Creates a user named after schema_name (like traditional creates from db_name)
	- Creates schema owned by this user
	- Handles PostgreSQL 15+ role membership requirements
	- Grants postgres user management rights
	- Adds Supabase role grants if they exist
	
	Args:
		schema_name: PostgreSQL schema name (also used as username).
	"""
	schema_name = _validate_schema_name(schema_name)
	
	# Like traditional mode: user name = schema name (mirrors db_name = user)
	site_user = schema_name
	site_password = frappe.conf.db_password
	root_user = frappe.flags.root_login
	
	root_conn = get_root_connection(frappe.flags.root_login, frappe.flags.root_password)
	root_conn.commit()
	root_conn.sql("end")
	
	# Create or update site user (same pattern as traditional mode)
	if root_conn.sql(f"SELECT 1 FROM pg_roles WHERE rolname='{site_user}'"):
		root_conn.sql(f"ALTER USER \"{site_user}\" WITH PASSWORD '{site_password}'")
	else:
		root_conn.sql(f"CREATE USER \"{site_user}\" WITH PASSWORD '{site_password}'")
	
	# Create schema
	root_conn.sql(f'CREATE SCHEMA IF NOT EXISTS "{schema_name}"')
	
	# Handle PostgreSQL 15+ role membership (same as traditional mode)
	if psql_version := root_conn.sql("SHOW server_version_num", as_dict=True):
		semver_version_num = psql_version[0].get("server_version_num") or "140000"
		if cint(semver_version_num) > 150000:
			admin_role = root_conn.sql("select current_user")[0][0]
			root_conn.sql(f'GRANT "{site_user}" TO "{admin_role}"')
			root_conn.commit()
			root_conn.close()
			frappe.local.flags.root_connection = None
			root_conn = get_root_connection(frappe.flags.root_login, frappe.flags.root_password)
	
	# Set site user as schema owner (mirrors database owner in traditional)
	root_conn.sql(f'ALTER SCHEMA "{schema_name}" OWNER TO "{site_user}"')
	
	# Grant privileges to site user
	root_conn.sql(f'GRANT ALL ON SCHEMA "{schema_name}" TO "{site_user}"')
	root_conn.sql(f'GRANT ALL ON ALL TABLES IN SCHEMA "{schema_name}" TO "{site_user}"')
	root_conn.sql(f'GRANT ALL ON ALL SEQUENCES IN SCHEMA "{schema_name}" TO "{site_user}"')
	root_conn.sql(f'GRANT ALL ON ALL ROUTINES IN SCHEMA "{schema_name}" TO "{site_user}"')
	
	# Default privileges for future objects
	root_conn.sql(f'ALTER DEFAULT PRIVILEGES IN SCHEMA "{schema_name}" GRANT ALL ON TABLES TO "{site_user}"')
	root_conn.sql(f'ALTER DEFAULT PRIVILEGES IN SCHEMA "{schema_name}" GRANT ALL ON SEQUENCES TO "{site_user}"')
	
	# Grant root user (postgres) management rights on schema
	if root_user and root_user != site_user:
		root_conn.sql(f'GRANT ALL ON SCHEMA "{schema_name}" TO "{root_user}"')
		root_conn.sql(f'GRANT ALL ON ALL TABLES IN SCHEMA "{schema_name}" TO "{root_user}"')
		root_conn.sql(f'GRANT ALL ON ALL SEQUENCES IN SCHEMA "{schema_name}" TO "{root_user}"')
	
	# Supabase-specific: Grant to anon, authenticated, service_role if they exist
	_grant_supabase_roles(root_conn, schema_name)
	
	root_conn.commit()
	root_conn.close()
	frappe.local.flags.root_connection = None
	
	# Update site_config with site user credentials (consistent with traditional)
	_update_site_config_for_schema_user(site_user, site_password)


def _grant_supabase_roles(conn, schema_name: str):
	"""Grant permissions to Supabase roles if they exist.
	
	These roles (anon, authenticated, service_role) exist on Supabase
	but not on regular PostgreSQL installations.
	"""
	supabase_roles = ["anon", "authenticated", "service_role"]
	
	for role in supabase_roles:
		# Check if role exists
		exists = conn.sql(f"SELECT 1 FROM pg_roles WHERE rolname = '{role}'")
		if not exists:
			continue
		
		# Grant schema access
		conn.sql(f'GRANT USAGE ON SCHEMA "{schema_name}" TO {role}')
		conn.sql(f'GRANT ALL ON ALL TABLES IN SCHEMA "{schema_name}" TO {role}')
		conn.sql(f'GRANT ALL ON ALL SEQUENCES IN SCHEMA "{schema_name}" TO {role}')
		conn.sql(f'GRANT ALL ON ALL ROUTINES IN SCHEMA "{schema_name}" TO {role}')
		
		# Default privileges for future objects
		conn.sql(f'ALTER DEFAULT PRIVILEGES IN SCHEMA "{schema_name}" GRANT ALL ON TABLES TO {role}')
		conn.sql(f'ALTER DEFAULT PRIVILEGES IN SCHEMA "{schema_name}" GRANT ALL ON SEQUENCES TO {role}')


def _update_site_config_for_schema_user(site_user: str, site_password: str):
	"""Update site_config.json with site user credentials."""
	import json
	from frappe.installer import get_site_config_path
	
	site_file = get_site_config_path()
	if os.path.exists(site_file):
		with open(site_file, 'r') as f:
			config = json.load(f)
		
		# Store site user (schema name) - consistent with traditional mode
		config['db_user'] = site_user
		config['db_password'] = site_password
		
		with open(site_file, 'w') as f:
			json.dump(config, f, indent=1, sort_keys=True)


def _setup_database_traditional():
	"""Original database creation logic (DROP/CREATE DATABASE).
	
	This is the traditional Frappe behavior for non-Supabase deployments.
	"""
	db_name = frappe.conf.db_name
	
	# Guard against dropping protected databases
	if db_name in PROTECTED_DATABASES:
		raise frappe.ValidationError(
			f"Cannot use protected database '{db_name}' without db_schema. "
			"Set db_schema in site_config.json to enable schema-based isolation."
		)
	
	root_conn = get_root_connection(frappe.flags.root_login, frappe.flags.root_password)
	root_conn.commit()
	root_conn.sql("end")
	root_conn.sql(f'DROP DATABASE IF EXISTS "{db_name}"')

	# If user exists, just update password
	if root_conn.sql(f"SELECT 1 FROM pg_roles WHERE rolname='{db_name}'"):
		root_conn.sql(f"ALTER USER \"{db_name}\" WITH PASSWORD '{frappe.conf.db_password}'")
	else:
		root_conn.sql(f"CREATE USER \"{db_name}\" WITH PASSWORD '{frappe.conf.db_password}'")
	root_conn.sql(f'CREATE DATABASE "{db_name}"')
	root_conn.sql(f'GRANT ALL PRIVILEGES ON DATABASE "{db_name}" TO "{db_name}"')
	if psql_version := root_conn.sql("SHOW server_version_num", as_dict=True):
		semver_version_num = psql_version[0].get("server_version_num") or "140000"
		if cint(semver_version_num) > 150000:
			admin_role = root_conn.sql("select current_user")[0][0]
			try:
				root_conn.sql(f'GRANT "{db_name}" TO "{admin_role}"')
				# Ensure role membership is visible for privilege checks in this session.
				root_conn.commit()
				root_conn.close()
				frappe.local.flags.root_connection = None
				root_conn = get_root_connection(frappe.flags.root_login, frappe.flags.root_password)
				can_set_role = root_conn.sql(
					"select pg_has_role(current_user, %s, 'set')", (db_name,)
				)
				if not (can_set_role and can_set_role[0][0]):
					raise Exception(
						f'Missing SET ROLE privilege for "{db_name}" as "{admin_role}"'
					)
				root_conn.sql(f'ALTER DATABASE "{db_name}" OWNER TO "{db_name}"')
				root_conn.commit()
			except Exception:
				# Remote managed Postgres may block role grants/ownership changes.
				raise
	root_conn.close()


def bootstrap_database(verbose, source_sql=None):
	frappe.connect()
	import_db_from_sql(source_sql, verbose)
	frappe.connect()

	if "tabDefaultValue" not in frappe.db.get_tables():
		import sys

		from click import secho

		secho(
			"Table 'tabDefaultValue' missing in the restored site. "
			"This happens when the backup fails to restore. Please check that the file is valid\n"
			"Do go through the above output to check the exact error message from MariaDB",
			fg="red",
		)
		sys.exit(1)


def import_db_from_sql(source_sql=None, verbose=False):
	if verbose:
		print("Starting database import...")
	
	db_name = frappe.conf.db_name
	db_schema = frappe.conf.get("db_schema")
	
	if not source_sql:
		source_sql = os.path.join(os.path.dirname(__file__), "framework_postgres.sql")
	
	if db_schema:
		# Schema mode: use the db_user from config (set by _update_site_config_credentials)
		# Prepend SET search_path to the SQL file
		import tempfile
		
		db_user = frappe.conf.get("db_user") or frappe.flags.root_login
		db_password = frappe.conf.get("db_password") or frappe.flags.root_password
		
		with open(source_sql, 'r') as f:
			original_sql = f.read()
		
		schema_sql = f'SET search_path TO "{db_schema}";\n\n' + original_sql
		
		with tempfile.NamedTemporaryFile(mode='w', suffix='.sql', delete=False) as tmp:
			tmp.write(schema_sql)
			tmp_path = tmp.name
		
		try:
			DbManager(frappe.local.db).restore_database(
				verbose, db_name, tmp_path, db_user, db_password
			)
		finally:
			os.unlink(tmp_path)
	else:
		# Traditional mode: user = db_name
		DbManager(frappe.local.db).restore_database(
			verbose, db_name, source_sql, db_name, frappe.conf.db_password
		)
	
	if verbose:
		print("Imported from database {}".format(source_sql))


def get_root_connection(root_login=None, root_password=None):
	if not frappe.local.flags.root_connection:
		if not root_login:
			root_login = frappe.conf.get("root_login") or None

		if not root_login:
			root_login = input("Enter postgres super user: ")

		if not root_password:
			root_password = frappe.conf.get("root_password") or None

		if not root_password:
			from getpass import getpass

			root_password = getpass("Postgres super user password: ")

		frappe.local.flags.root_connection = frappe.database.get_db(
			socket=frappe.conf.db_socket,
			host=frappe.conf.db_host,
			port=frappe.conf.db_port,
			user=root_login,
			password=root_password,
			cur_db_name=root_login,
		)

	return frappe.local.flags.root_connection


def drop_user_and_database(db_name, root_login, root_password):
	root_conn = get_root_connection(
		frappe.flags.root_login or root_login, frappe.flags.root_password or root_password
	)
	root_conn.commit()
	root_conn.sql(
		"SELECT pg_terminate_backend (pg_stat_activity.pid) FROM pg_stat_activity WHERE pg_stat_activity.datname = %s",
		(db_name,),
	)
	root_conn.sql("end")
	root_conn.sql(f"DROP DATABASE IF EXISTS {db_name}")
	root_conn.sql(f"DROP USER IF EXISTS {db_name}")
