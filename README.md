# TD_Balances
Download historical transactions, process them with FIFO/LIFO, and calculate actual balances.

To make it work, download chromedriver.exe and place it in the same folder.

user.data.json:
- user: Used to store the Refresh token.
- client_id: Obtained from the TD developer API.
- redirect_uri: Generally "http://localhost/test," but when the client_id is generated, a different one can be chosen.
