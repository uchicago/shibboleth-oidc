INSERT INTO authorities_TEMP (username, authority) VALUES
  ('admin','ROLE_ADMIN'),
  ('admin','ROLE_USER'),
  ('user','ROLE_USER');
    
-- By default, the username column here has to match the username column in the users table, above
INSERT INTO user_info_TEMP (sub, preferred_username, name, email, email_verified, given_name, family_name) VALUES
  ('90342.ASDFJWFA','admin','Demo Admin','admin@example.com', true, 'Lasbrey', 'Nwachukwu'),
  ('01921.FLANRJQW','user','Demo User','user@example.com', true, 'Test', 'Lastname');


