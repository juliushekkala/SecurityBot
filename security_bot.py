import os

import discord
from dotenv import load_dotenv

from bot_utils import *
from phishtank import PhishTank
from file_scanner import scan_file

load_dotenv()
TOKEN = os.getenv('DISCORD_TOKEN')
GUILD = os.getenv('DISCORD_GUILD')
APIKEY = os.getenv('PHISHTANK_API_KEY')

client = discord.Client()

db, db_status = PhishTank().get_phistank_db(APIKEY)

#Config load/creation
config = getConfig()


@client.event
async def on_ready():
    guild = discord.utils.get(client.guilds, name=GUILD)
    print(f'{client.user} has connected to Discord!')
    print(f'Guild is: {guild.name}, {guild.id}')

''' On client message, the bot should check whether there are extensions and/or links '''
@client.event 
async def on_message(message):
    global db
    global db_status

    #ignore own messages
    if message.author == client.user:
        return 

    if message.content == "test":
        response = "Test succesful"
        await message.channel.send(response)

    #for faster testing, exit when user types "bye"
    if message.content == "bye":
        exit(0)

    if message.content.startswith("!"):
        #might be a command
        if message.content == "!secbot":
            #Provide info on bots current status and settings
            response = "Current config: \n"
            response += "Automatic scanning: " + str(config.getboolean("SCAN", "autoscan")) + "\n"
            if config.getboolean("BOTREACT", "msgokreact"):
                response += "Bot adds a reaction to safe links and attachments. \n"
            if config.getboolean("BOTREACT", "msgokanswer"):
                response += "Bot answers to safe links and messages. \n"
            if config.getboolean("SCAN", "scanfile") and config.getboolean("SCAN", "scanlink"):
                response += "Both links and files are checked. \n"
            elif config.getboolean("SCAN", "scanfile"):
                response += "Files are checked. \n"
            elif config.getboolean("SCAN", "scanlink"):
                response += "Links are checked. \n"
            if config.getboolean("SCAN", "pdfscan"):
                response += "Proof-of-concept checking of PDF files is enabled."
            await message.channel.send(response)
        elif message.content == "!secbotadmin":
            #Provide extra info about bot, for debugging and setting up
            response = "Current config: \n"
            response += "GUILD = " + GUILD + "\n"
            # Print config. Adapted from https://stackoverflow.com/a/50362738
            configstring = str({section: dict(config[section]) for section in config.sections()})
            response += configstring
            await message.channel.send(response)
        elif message.content == "!check":
            #Check previous message for links and files
            if message.reference is not None:
                channel = client.get_channel(message.reference.channel_id)
                suspmessageid = message.reference.message_id
                suspmessage = await channel.fetch_message(suspmessageid)
                print(suspmessage.content)
                await checkMessage(suspmessage)
        elif message.content == "!sechelp":
            #List available commands for the user in question
            response = "Hello! I am a security focused Discord Bot that checks links and files for dangerous elements.\n!secbot provides specific settings used in this server. \n!check can be used in a reply to verify a previous message"
            await message.channel.send(response)
        elif message.content == "!dbstatus":
            response = "Phishing database status: {} \n Last updated: {}\n Status code: {}".format(db_status["status"], db_status["datetime"], db_status["status_code"])
            await message.channel.send(response)
        elif message.content == "!dbupdate":
            db, db_status = PhishTank().get_phistank_db(APIKEY)
            response = "Phishing database update result: {}\n Status code: {}".format(db_status["status"], db_status["status_code"])
            await message.channel.send(response)
    if config.getboolean("SCAN", "autoscan"):
        await checkMessage(message)

async def checkMessage(message):
    global db
    global db_status

    safe = True
    checked = False

    # Check if links exist in message
    urls_list = findURLs(message.content)

    if config.getboolean("SCAN", "scanlink") and (len(urls_list) != 0):

        # Checks for database errors and if database is up to date
        if db_status["status"] == 'DatabaseError' or not(PhishTank().db_up_to_date(db_status["datetime"])):
            if not(PhishTank().db_up_to_date(db_status["datetime"])):
                db, db_status = PhishTank().get_phistank_db(APIKEY)

        # Checks links in a list against up to date phishing site database
        if len(urls_list) != 0 and db_status["status"] != 'DatabaseError':
            urls_info = PhishTank().check_urls(urls_list, db)
            response = PhishTank().parse_response(urls_info)
            checked = True
            if response is not None:
                safe = False
                

    if config.getboolean("SCAN", "scanfile"):
        # If there is an attachment
        if message.attachments is not None:
            for attachment in message.attachments:
                print("\nAttachment detected\n")
                print(attachment.filename)
                #Save the attachment
                await attachment.save(attachment.filename)
                #Check if the attachment is secure
                is_secure = await scan_file(attachment.filename, config)
                #Lastly, delete the file 
                os.remove(attachment.filename)
                checked = True
                if not is_secure:
                    safe = False
    
    if not safe:
        # Delete message
        await message.delete()
        response = "Possibly dangerous message was deleted"
        await message.channel.send(response)
    elif safe and checked:
        # Nothing harmful found
        if config.getboolean("BOTREACT", "msgokanswer"):
            response = "Nothing dangerous found in message"
            await message.channel.send(response)
        # Add react here
        if config.getboolean("BOTREACT", "msgokreact"):
            emoji = config.get("BOTREACT", "msgokreacttype")
            await message.add_reaction(emoji)


client.run(TOKEN)
