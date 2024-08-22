import customtkinter
import sqlite3
from cryptography.fernet import Fernet

# Formatting
customtkinter.set_appearance_mode('dark')
customtkinter.set_default_color_theme('dark-blue')

# Building Initial window
login_window = customtkinter.CTk()
login_window.geometry('300x275')
login_window.resizable(False, False)
login_window.title('Password Manager Login Window')

# Initiating sql databases
account_log = sqlite3.connect('accountLog.db')
cursor_al = account_log.cursor()
cursor_al.execute('''
CREATE TABLE IF NOT EXISTS accountList 
    (username TEXT PRIMARY KEY,
    password TEXT)
''')
account_log.commit()

# Trying to read a file that my not exist depending on weither a user has used this program before
try:
    # Gets the key from the file if the user has used the program before
    with open("encryption_key.key", "rb") as key_file:
        key = key_file.read()

# If a user has not used the program before they will get an error for reading so this handles that 
except FileNotFoundError:
    # Makes a new key to save and to be read the next time the program is opened to use that key again
    key = Fernet.generate_key()

    with open("encryption_key.key", "wb") as key_file:
        key_file.write(key)

# Creates the cipher
cipher_suite = Fernet(key)

# Initiataing the variable for an error message
error_message = conf = None

# Creating an update Variable
update_var = False

# Fixes any closing out bugs
def on_closing():
    pass_man.destroy()
    quit()

def login():
    # Get the information that was given
    username = username_entry.get()
    password = password_entry.get()

    global error_message

    if error_message:
        error_message.destroy()

    # Makes sure both the password and the username were filled out
    if username and password:
        # Both fields have been filled out

        try:
            # See if the username is an entry in the db and then takes the encrypted password and decrypts it
            cursor_al.execute('SELECT password FROM accountList WHERE username=?',  (username,))
            enc_pass = cursor_al.fetchone()[0]
            dc_pass = cipher_suite.decrypt(enc_pass).decode()

            # Decrypted password vs user input
            if password == dc_pass:
                # Correct password
                #and makes the new window for the password info
                global pass_man
                global update_var

                update_var = True

                pass_man = customtkinter.CTk()
                pass_man.geometry('1050x650')
                pass_man.resizable(False, True)
                pass_man.title(username + '\'s Password Manager')

                # Destroys origianal window 
                login_window.withdraw()
                login_window.quit()

            else:
                # Incorrect password
                error_message = customtkinter.CTkLabel(master=frame, text='Password Incorrect', text_color='red')
                error_message.pack()

        
        except:
            # If the username does not exist it will produce an error so this will take care of that and prompt another entry
            error_message = customtkinter.CTkLabel(master=frame, text='Username does not exist.', text_color='red')
            error_message.pack()


    elif password:
        # Username is not filled out
        error_message = customtkinter.CTkLabel(master=frame, text='Please enter the Username.', text_color='red')
        error_message.pack()

    elif username:
        # Password was not filled out
        error_message = customtkinter.CTkLabel(master=frame, text='Please enter the Password.', text_color='red')
        error_message.pack()

    else:
        # Both are nor filled out
        error_message = customtkinter.CTkLabel(master=frame, text='Please enter the Username and Password.', text_color='red')
        error_message.pack()


def signup():
    # Get the information that was given
    username = username_entry.get()
    password = password_entry.get()

    global error_message
    result = 0

    # Check if there are any errors that have happend and destroiest them to not cause repacking of the same error message
    if error_message:
        error_message.destroy()

    # Makes sure both the password and the username were filled out
    if username and password:
        # Both fields have been filled out
        # Checking if the account /  username exists
        cursor_al.execute('''SELECT EXISTS(SELECT 1 FROM accountList WHERE username = ?)''', (username,))
        result = cursor_al.fetchone()[0]

        if result:
            # Telling the user that the username exists
            error_message = customtkinter.CTkLabel(master=frame, text='An account with this username exists.', text_color='red')
            error_message.pack()

        else:
            # Creating the account with an encrypted password
            encrypted_password = cipher_suite.encrypt(password.encode())
            cursor_al.execute('INSERT INTO AccountList (username, password) VALUES (?,?)', (username, encrypted_password))
            account_log.commit()

            error_message = customtkinter.CTkLabel(master=frame, text='The account has been made.', text_color='white')
            error_message.pack()

    elif password:
        # Username is not filled out
        error_message = customtkinter.CTkLabel(master=frame, text='Please enter the Username.', text_color='red')
        error_message.pack()

    elif username:
        # Password was not filled out
        error_message = customtkinter.CTkLabel(master=frame, text='Please enter the Password.', text_color='red')
        error_message.pack()

    else:
        # Both are nor filled out
        error_message = customtkinter.CTkLabel(master=frame, text='Please enter the Username and Password.', text_color='red')
        error_message.pack()


def clear_all_widgets():
    # This will reset the windows everytime a new tab is opend
    for widget in pass_man.winfo_children():
        if isinstance(widget, customtkinter.CTkEntry):
            widget.grid_remove()
        elif isinstance(widget, customtkinter.CTkLabel):
            widget.grid_remove()
        elif isinstance(widget, customtkinter.CTkTextbox):
            widget.grid_remove()
        elif isinstance(widget, customtkinter.CTkButton):
            widget.grid_remove()


def accounts():
    # Clears the pass_man window from all the widgets
    clear_all_widgets()

    # Show all accounts + account information
    user_info_textbox = customtkinter.CTkTextbox(master=pass_man, font=("Arial", 16))
    user_info_textbox.grid(row=2, column=1, pady=20, padx=20, sticky="nsew")

    cursor_mf.execute('SELECT * from userinfo')
    rec = cursor_mf.fetchall()
    user_info_textbox.delete(0.0)
    for r in rec:
        user_info_textbox.insert('end', f'App: {r[0]}    -    Username: {r[1]}    -    Password: {cipher_suite.decrypt(r[2]).decode()}\n\n')


def open():
    # Clears the pass_man window from all the widgets
    clear_all_widgets()

    # Creates the infustructure for the adding funtion
    entry_site_name = customtkinter.CTkEntry(master=pass_man, placeholder_text='Program / Site')
    entry_site_name.grid(row=0, column=1, pady=20, padx=20, sticky='ew')
    
    # This button initiates the open function
    op_bt = customtkinter.CTkButton(master=pass_man, text='Open', command=lambda: open_log(entry_site_name))
    op_bt.grid(row=0, column=2, pady=10, padx=20)


def edit():
    # Clears the pass_man window from all the widgets
    clear_all_widgets()

    # Creates the infustructure for the adding funtion
    entry_site_name = customtkinter.CTkEntry(master=pass_man, placeholder_text='Program / Site')
    entry_site_name.grid(row=0, column=1, pady=20, padx=20, sticky='ew')
    entry_site_username = customtkinter.CTkEntry(master=pass_man, placeholder_text='New Username')
    entry_site_username.grid(row=0, column=2, pady=20, padx=20, sticky='ew')
    entry_site_pass = customtkinter.CTkEntry(master=pass_man, placeholder_text='New Password',  show='*')
    entry_site_pass.grid(row=0, column=3, pady=20, padx=20, sticky='ew')

    # The button initiates the edit to take place
    up_bt = customtkinter.CTkButton(master=pass_man, text='Update', command=lambda: edit_log(entry_site_name, entry_site_username, entry_site_pass))
    up_bt.grid(row=0, column=4, pady=10, padx=20)


def add():
    # Clears the pass_man window from all the widgets
    clear_all_widgets()

    # Creates the infustructure for the adding funtion
    entry_site_name = customtkinter.CTkEntry(master=pass_man, placeholder_text='Program / Site')
    entry_site_name.grid(row=0, column=1, pady=20, padx=20, sticky='ew')
    entry_site_username = customtkinter.CTkEntry(master=pass_man, placeholder_text='Username')
    entry_site_username.grid(row=0, column=2, pady=20, padx=20, sticky='ew')
    entry_site_pass = customtkinter.CTkEntry(master=pass_man, placeholder_text='Password',  show='*')
    entry_site_pass.grid(row=0, column=3, pady=20, padx=20, sticky='ew')

    # The button that initiates the adding prosses to the log
    dn_bt = customtkinter.CTkButton(master=pass_man, text='Add', command=lambda: add_to_log(entry_site_name, entry_site_username, entry_site_pass))
    dn_bt.grid(row=0, column=4, pady=10, padx=20)


def delete():
    # Clears the pass_man window from all the widgets
    clear_all_widgets()

    # Creates the infustructure for the adding funtion
    entry_site_name = customtkinter.CTkEntry(master=pass_man, placeholder_text='Program / Site')
    entry_site_name.grid(row=0, column=1, pady=20, padx=20, sticky='ew')

    # The button initiates the delelte to take place
    dl_bt = customtkinter.CTkButton(master=pass_man, text='Delete', command=lambda: delete_log(entry_site_name))
    dl_bt.grid(row=0, column=3, pady=10, padx=20)


def open_log(site):
    # Gets teh site name from the tab function
    site_name = site.get()

    # Makes a text box where the opened log will show up
    user_info_textbox = customtkinter.CTkTextbox(master=pass_man, font=("Arial", 16))
    user_info_textbox.grid(row=2, column=1, columnspan=2, pady=20, padx=20, sticky="nsew")
    
    # Open the full log with the site name
    cursor_mf.execute('SELECT * FROM USERINFO WHERE app=?', (site_name,))
    rec = cursor_mf.fetchone()

    # Shows the log if it exist and if it does not then it will return a error message
    try:
        user_info_textbox.delete(0.0)
        user_info_textbox.insert('end', f'App: {rec[0]}    -    Username: {rec[1]}    -    Password: {cipher_suite.decrypt(rec[2]).decode()}\n\n')
    except:
        user_info_textbox.delete(0.0)
        user_info_textbox.insert(0.0, 'This information is not logged.')


def edit_log(site, user, password):
    # Gets the information from the button creation page
    site_name = site.get()
    site_user = user.get()
    site_pass = password.get()

    # Makes the text box where the edited information will show up
    user_info_textbox = customtkinter.CTkTextbox(master=pass_man, font=("Arial", 16))
    user_info_textbox.grid(row=2, column=1, columnspan=4, pady=20, padx=20, sticky="nsew")
    
    # Update and edit the log based on the site name and new password or gives an error if the account doesn't exist
    try:
        if site_user and site_pass:
            cursor_mf.execute('UPDATE userinfo SET username=? WHERE app=?', (site_user, site_name))
            cursor_mf.execute('UPDATE userinfo SET password=? WHERE app=?', (cipher_suite.encrypt(site_pass.encode()), site_name))
        elif site_pass:
            cursor_mf.execute('UPDATE userinfo SET password=? WHERE app=?', (cipher_suite.encrypt(site_pass.encode()), site_name))
        elif site_user:
            cursor_mf.execute('UPDATE userinfo SET username=? WHERE app=?', (site_user, site_name))

        cursor_mf.execute('SELECT * FROM userinfo WHERE app=?', (site_name,))
        rec = cursor_mf.fetchone()

        user_info_textbox.delete(0.0, 'end')
        user_info_textbox.insert('end', f'App: {rec[0]}    -    Username: {rec[1]}    -    Password: {cipher_suite.decrypt(rec[2]).decode()}\n\n')

    except Exception as e:
        print(e)
        user_info_textbox.delete(0.0, 'end')
        user_info_textbox.insert('end', 'This information is not logged.')


def add_to_log(site, user, password):
    # Gets rid of the error / confermation message if there are one or more additions to the log
    global conf

    if conf:
        conf.grid_forget()

    # Gets the information that the user gave in the add function
    site_name = site.get()
    site_user = user.get()
    site_pass = password.get()

    # Checks to see if there is a log of the app that is being inputed
    cursor_mf.execute('''SELECT EXISTS(SELECT 1 FROM userinfo WHERE app = ?)''', (site_name,))
    r = cursor_mf.fetchone()[0]

    # If there is a log of the app that is inputed
    if r:
        conf = customtkinter.CTkLabel(master=pass_man, text='There is a log with this Program. Check the Password on the Open tab, or edit the Log on the Edit tab.', text_color='red')
        conf.grid(row=1, column=1, pady=10, padx=20, columnspan=3, sticky='ew')

    # If there is no log of the inputed app name it will log it and encrypt the password using the key
    else:
        # Take the password and use the original key to encrypt it so we can store the encrypted password
        site_pass_enc = cipher_suite.encrypt(site_pass.encode())

        # Adds the information given to the log
        cursor_mf.execute('''
        INSERT INTO userinfo (app, username, password) VALUES (?, ?, ?)''', (site_name, site_user, site_pass_enc))
        mainframe_acc.commit()

        # Gives a visual green text message on the add tab to show that the addition is compleat
        conf = customtkinter.CTkLabel(master=pass_man, text='Your Information has been Added!', text_color='green')
        conf.grid(row=1, column=1, pady=10, padx=20, columnspan=3, sticky='ew')


def delete_log(site):
    site_name = site.get()
    
    # Delete the record of the log based on the site name
    global conf

    if conf:
        conf.grid_forget()

    # Checks to see if there is a log of the app that is being inputed
    cursor_mf.execute('''SELECT EXISTS(SELECT 1 FROM userinfo WHERE app = ?)''', (site_name,))
    r = cursor_mf.fetchone()[0]

    # Deletes the account if it exists and if it does not then it will return and error
    if r:
        cursor_mf.execute('DELETE FROM userinfo WHERE app=?', (site_name,))
        conf = customtkinter.CTkLabel(master=pass_man, text='The account log has been deleted!', text_color='green')
        conf.grid(row=1, column=1, pady=10, padx=20, columnspan=3, sticky='ew')

    else:
        conf = customtkinter.CTkLabel(master=pass_man, text='This app / program / site does not have a linked account.', text_color='green')
        conf.grid(row=1, column=1, pady=10, padx=20, columnspan=3, sticky='ew')


def logout():
    quit()
    

# Login and signup interface sceleton
frame = customtkinter.CTkFrame(master=login_window)
frame.pack(fill='both')
appname_label = customtkinter.CTkLabel(master=frame, text='Password Manager', font=('Roboto', 20))
appname_label.pack(pady=12, padx=40)

username_entry = customtkinter.CTkEntry(master=frame, placeholder_text='Username')
username_entry.pack(pady=12, padx=40)
password_entry = customtkinter.CTkEntry(master=frame, placeholder_text='Password', show='*')
password_entry.pack(pady=12, padx=40)

login_button = customtkinter.CTkButton(master=frame, text='Login', command=login)
login_button.pack(pady=6, padx=40)
signup_button = customtkinter.CTkButton(master=frame, text='Sign-Up', command=signup)
signup_button.pack(pady=12, padx=40)

login_window.mainloop()

# Prevents error if user does not go though with using the program
try:

    # Checks if the log in was succsesful
    if update_var:
        # Fixes any closing out bugs
        pass_man.protocol('WM_DELETE_WINDOW', on_closing)

        # Open or create the database of the user
        username = username_entry.get()
        mainframe_acc = sqlite3.connect(username + '_info.db')
        cursor_mf = mainframe_acc.cursor()
        cursor_mf.execute('''
        CREATE TABLE IF NOT EXISTS userinfo 
            (app TEXT PRIMARY KEY,
            username TEXT,
            password TEXT)
        ''')
        mainframe_acc.commit()

        nav_frame = customtkinter.CTkFrame(master=pass_man)
        nav_frame.grid(row=0, column=0, rowspan=3, sticky="ns")
        nav_frame.grid_rowconfigure(7, weight=1)
        name_label = customtkinter.CTkLabel(master=nav_frame, text=username + '\'s Passwords')
        name_label.grid(row=0, column=0, pady=20, padx=20)

        # Add buttons to the navigation frame
        account_button = customtkinter.CTkButton(master=nav_frame, text='Accounts', command=accounts)
        account_button.grid(row=1, column=0, pady=10, padx=20)

        open_button = customtkinter.CTkButton(master=nav_frame, text='Open', command=open)
        open_button.grid(row=2, column=0, pady=10, padx=20)

        edit_button = customtkinter.CTkButton(master=nav_frame, text='Edit', command=edit)
        edit_button.grid(row=3, column=0, pady=10, padx=20)

        add_button = customtkinter.CTkButton(master=nav_frame, text='Add', command=add)
        add_button.grid(row=4, column=0, pady=10, padx=20)

        del_button = customtkinter.CTkButton(master=nav_frame, text='Delete', command=delete)
        del_button.grid(row=5, column=0, pady=10, padx=20)

        log_out_button = customtkinter.CTkButton(master=nav_frame, text='Log Out',command=logout)
        log_out_button.grid(row=8, column=0, pady=(10, 30), padx=20, sticky='s')

        # Configure row and column weights for proper resizing
        pass_man.grid_columnconfigure(1, weight=1)
        pass_man.grid_rowconfigure(2, weight=1)

        pass_man.mainloop()

except:
    # Closes the program out
    quit()
