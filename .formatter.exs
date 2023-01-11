spark_locals_without_parens = [
  api: 1,
  auth0: 0,
  auth0: 1,
  auth0: 2,
  auth_method: 1,
  authorization_params: 1,
  authorize_path: 1,
  client_id: 1,
  client_secret: 1,
  confirm_action_name: 1,
  confirm_on_create?: 1,
  confirm_on_update?: 1,
  confirmation: 0,
  confirmation: 1,
  confirmation: 2,
  confirmation_required?: 1,
  confirmed_at_field: 1,
  enabled?: 1,
  expunge_expired_action_name: 1,
  expunge_interval: 1,
  get_by_subject_action_name: 1,
  get_changes_action_name: 1,
  get_token_action_name: 1,
  hash_provider: 1,
  hashed_password_field: 1,
  identity_field: 1,
  identity_relationship_name: 1,
  identity_relationship_user_id_attribute: 1,
  identity_resource: 1,
  inhibit_updates?: 1,
  is_revoked_action_name: 1,
  monitor_fields: 1,
  oauth2: 0,
  oauth2: 1,
  oauth2: 2,
  password: 0,
  password: 1,
  password: 2,
  password_confirmation_field: 1,
  password_field: 1,
  password_reset_action_name: 1,
  private_key: 1,
  read_expired_action_name: 1,
  redirect_uri: 1,
  register_action_name: 1,
  registration_enabled?: 1,
  request_password_reset_action_name: 1,
  require_token_presence_for_authentication?: 1,
  resettable: 0,
  resettable: 1,
  revoke_token_action_name: 1,
  sender: 1,
  sign_in_action_name: 1,
  signing_algorithm: 1,
  signing_secret: 1,
  site: 1,
  store_all_tokens?: 1,
  store_changes_action_name: 1,
  store_token_action_name: 1,
  subject_name: 1,
  token_lifetime: 1,
  token_path: 1,
  token_resource: 1,
  user_path: 1
]

[
  import_deps: [:ash, :spark, :ash_json_api, :ash_graphql],
  inputs: [
    "*.{ex,exs}",
    "{dev,config,lib,test}/**/*.{ex,exs}"
  ],
  plugins: [Spark.Formatter],
  locals_without_parens: spark_locals_without_parens,
  export: [
    locals_without_parens: spark_locals_without_parens
  ]
]
