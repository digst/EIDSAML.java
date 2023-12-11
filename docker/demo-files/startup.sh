#!/bin/bash

echo $DEMO_ENTITY_ID
find . -type f \( -iname \*.xml -o -iname \*.properties \) -exec sed -i -e "s|{DEMO_ENTITY_ID}|$DEMO_ENTITY_ID|g" {} \;

echo $DEMO_BASE_URL
find . -type f \( -iname \*.xml -o -iname \*.properties \) -exec sed -i -e "s|{DEMO_BASE_URL}|$DEMO_BASE_URL|g" {} \;

echo $EID_IDP_URL
find . -type f \( -iname \*.xml -o -iname \*.properties \) -exec sed -i -e "s|{EID_IDP_URL}|$EID_IDP_URL|g" {} \;

mvn clean install -DskipTests