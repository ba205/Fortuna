#!/bin/sh

ps -e > ps.txt
stack CatDevRandom.hs
