import sqlite3  
  
con = sqlite3.connect("hospital.db")  
# print("Database opened successfully")  
# con.execute('Drop table Hospital')
# con.execute("create table Hospital (Patient_id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, Bed_no Integer UNIQUE NOT NULL, Phone_no Integer NOT NULL, Emergency_contact_name TEXT NOT NULL, Emergency_contact_no INTEGER NOT NULL, Status TEXT NOT NULL, Is_deleted TEXT NOT NULL)")  

# print("Table created successfully")
cur=con.cursor()
#cur.execute("""SELECT name FROM sqlite_master
#   WHERE type='table';""")
# cur.execute('DELETE FROM Hospital WHERE Patient_id= 13')
# Patient_id=11
# with sqlite3.connect("hospital.db") as con:  
#         try:  
#             cur = con.cursor()  
#             cur.execute("delete from Hospital where Patient_id = ?",[Patient_id])  
#             msg = "record successfully deleted"  
#         except Exception as e: 
#             print(e)
#             msg = "can't be deleted" 

cur.execute('DROP TABLE Hospital')
print('Done')
rows=cur.fetchall()
print(rows)
#print(cur.fetchall())
# cur.execute('Select * from user')
# print(cur.fetchall())
con.close()  