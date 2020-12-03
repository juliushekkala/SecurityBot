import os

import discord
from dotenv import load_dotenv

from bot_utils import *
from phishtank import PhishTank
from file_scanner import scan_file

load_dotenv()
TOKEN = os.getenv('DISCORD_TOKEN')
GUILD = os.getenv('DISCORD_GUILD')

client = discord.Client()
db = PhishTank().get_phistank_db()

@client.event
async def on_ready():
    guild = discord.utils.get(client.guilds, name=GUILD)
    print(f'{client.user} has connected to Discord!')
    print(f'Guild is: {guild.name}, {guild.id}')

''' On client message, the bot should check whether there are extensions and/or links '''
@client.event 
async def on_message(message):
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
            pass
        elif message.content == "!secbotadmin":
            #Provide extra info about bot, for debugging setting up
            pass
        elif message.content == "!check":
            #Check previous message for links and files
            pass
        elif message.content == "!sechelp":
            #List available commands for the user in question
            pass
    # Check if links exist in message
    urls_list = findURLs(message.content)
    # Checks links in a list against phishing site database
    if len(urls_list) != 0:
        urls_info = PhishTank().check_urls(urls_list, db)
        response = PhishTank().parse_response(urls_info)
        if response is not None:
            await message.channel.send(response)
    #If there is an attachment
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
            #TODO: Figure out a good way to indicate that the file was checked
            else:
                pass

client.run(TOKEN)
