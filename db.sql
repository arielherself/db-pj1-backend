CREATE TABLE auth_user (
    id serial PRIMARY KEY,
    name character varying(255) NOT NULL,
    password character varying(255) NOT NULL,
    email character varying(255) NOT NULL UNIQUE
);

CREATE TABLE restaurants (
    id serial PRIMARY KEY,
    user_id integer references auth_user,
    name character varying(255) NOT NULL,
    address character varying(255) NOT NULL,
    contact character varying(255) NOT NULL
)
