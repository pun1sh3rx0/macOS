#!/bin/bash

whoami && hostname && ifconfig en0 | grep "inet " | awk '{print $2}' 
