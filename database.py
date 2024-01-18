import pypyodbc as odbc
import pandas as pd

class Database:
    """
    Call to config the and establish a connection for AZURE SQL Database
    """

    def __init__(self) -> None:
        self.server = 'product-db.database.windows.net'
        self.database = 'project1'
        self.user = 'CloudSAeefe3a29'
        self.password = 'Test@12345'

        self.connection_string = f'Driver={{ODBC Driver 18 for SQL Server}};\
                                Server={self.server};\
                                Database={self.database};Uid={self.user};\
                                Pwd={self.password};Encrypt=yes;\
                                TrustServerCertificate=no;Connection Timeout=30;'
        

    def get_result(self, query, dataframe = False, params = ()):
        con = odbc.Connection(self.connection_string)
        cursor = con.cursor()
        if params:
            cursor.execute(query, params)
            if dataframe:
                res = pd.DataFrame(cursor.fetchall())
                return res
            res = cursor.fetchall()
            return res
        else:
            cursor.execute(query)
            con.commit()
            con.close()
            return 'Success'
"""       

if __name__ == "__main__":
    db_obj = Database()
    param = 'vinay'
    query = '''
            select * from login_users where user_name = ?;
            '''
    result = db_obj.get_result(query=query, params=[param])
    print(result)
"""