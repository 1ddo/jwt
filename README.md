# JWT
## Dev Phase

## How to test

Prerequisites
* Install Postman for testing purposes
* Install Postgres
    * Start postgres service
        * Using brew - "brew services start postgres@version"
    * Run the following SQL Commands (You can use any sql client or run "psql postgre" command)
        ~~~
        CREATE ROLE goalert WITH LOGIN PASSWORD 'root';

        ALTER ROLE goalert CREATEDB;
        ~~~

    * Login as goalert (via sql client or using the command "psql -U goalert" command)
    * Run the following commands:
        ~~~
        CREATE TABLE goa_api_key ( api_key VARCHAR PRIMARY KEY, api_user VARCHAR(100) NOT NULL, status VARCHAR(10) NOT NULL, created_time timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP );

        INSERT INTO public.goa_api_key VALUES('gZKTbUDDZoA=', 'iddukey2', 'A');
        ~~~

1. Go to the project directory and run the following command:
    ```
    go run *.go
    ```
2. Open postman and import the .json file from the project directory (jwt -> postman)
    * After importing the .json file, postman will load requests
        * The "jwt" request will be be used to request new token
        * The "hello" will be used for testing the new token 
        * The "new/apikey" will be used for adding new api keys
        * THe "apikeys" will be used for retrieving existing api keys
3. Open the "jwt" request. From the Headers tab, you'll see the "Access" and the "Token-No-Expiry" headers.
    * "Access" header is used for validating that the user is listed in the "goa_api_key" table as a valid user.
        * Default Value: iddukey  
    * "Token-No-Expiry" header is used as flag to tell the JWT request to be a non expirty token. Note that this is an optional header.
    If this header is not set, the Token is set to expired after 24hrs
        * Default Value: empty
4. Click the "Send" button and you'll see a response "token" values or a "Not Authorized" value if user is not authorized/valid.
5. Now, open the "hello" request. From the Header tab, you'll see the "Token" header. This header will be used for sending the token value from the "jwt" request.
6. Click the "Send" button and you should be able to see a response "Hello World" value or "Not Authorized" if token is invalid.

