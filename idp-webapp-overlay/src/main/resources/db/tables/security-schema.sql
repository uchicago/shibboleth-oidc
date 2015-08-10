--
-- Licensed to the University Corporation for Advanced Internet Development,
-- Inc. (UCAID) under one or more contributor license agreements.  See the
-- NOTICE file distributed with this work for additional information regarding
-- copyright ownership. The UCAID licenses this file to You under the Apache
-- License, Version 2.0 (the "License"); you may not use this file except in
-- compliance with the License.  You may obtain a copy of the License at
--
--    http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--

-- 
-- Tables for Spring Security's user details service
--
  
create table IF NOT EXISTS users(
      username varchar(50) not null primary key,
      password varchar(50) not null,
      enabled boolean not null);

  create table IF NOT EXISTS authorities (
      username varchar(50) not null,
      authority varchar(50) not null,
      constraint fk_authorities_users foreign key(username) references users(username),
      constraint ix_authority unique (username,authority));