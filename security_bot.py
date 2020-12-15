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
                response += "Both links are files are checked. \n"
            elif config.getboolean("SCAN", "scanfile"):
                response += "Files are checked. \n"
            elif config.getboolean("SCAN", "scanlink"):
                response += "Links are checked. \n"
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
            channel = client.get_channel(message.reference.channel_id)
            suspmessageid = message.reference.message_id
            suspmessage = await channel.fetch_message(suspmessageid)
            print(suspmessage.content)
            #TODO: Message checking here
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

    # Check if links exist in message
    urls_list = findURLs(message.content)

    # Checks for database errors and if database is up to date
    if db_status["status"] == 'DatabaseError' or not(PhishTank().db_up_to_date(db_status["datetime"])):
        if not(PhishTank().db_up_to_date(db_status["datetime"])):
            db, db_status = PhishTank().get_phistank_db(APIKEY)

    # Checks links in a list against up to date phishing site database
    if len(urls_list) != 0 and db_status["status"] != 'DatabaseError':
        urls_info = PhishTank().check_urls(urls_list, db)
        response = PhishTank().parse_response(urls_info)
        if response is not None:
            await message.channel.send(response)

    # If there is an attachment
    if message.attachments is not None:
        for attachment in message.attachments:
            print("\nAttachment detected\n")
            print(attachment.filename)
            #Save the attachment
            await attachment.save(attachment.filename)
            #Check if the attachment is secure
            is_secure = await scan_file(attachment.filename)
            #Lastly, delete the file 
            os.remove(attachment.filename)

            #If the attachment was not secure, delete the message
            if not is_secure:
                await message.delete()
                response = "Evil file was deleted by me, your friendly bot"
                await message.channel.send(response)
            #TODO: Figure out a good way to indicate that the file was checked
            else:
                pass

client.run(TOKEN)
