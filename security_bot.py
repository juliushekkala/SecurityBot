import os

import discord
from dotenv import load_dotenv

load_dotenv()
TOKEN = os.getenv('DISCORD_TOKEN')
GUILD = os.getenv('DISCORD_GUILD')

client = discord.Client()

@client.event
async def on_ready():
    guild = discord.utils.get(client.guilds, name=GUILD)
    print(f'{client.user} has connected to Discord!')
    print(f'Guild is: {guild.name}, {guild.id}')

@client.event 
async def on_message(message):
    #ignore own messages
    if message.author == client.user:
        return 
    if message.content == "test":
        response = "Test succesful"
        await message.channel.send(response)


client.run(TOKEN)
