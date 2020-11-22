import requests
import json
import pprint
import base64
import hashlib
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA


#Server url
#URL = "http://185.115.217.205:1234"
URL = "http://bennyserver.xyz:8000"

def opdracht1():
    #eerste opdracht url
    response = requests.get(url = (URL + "/opdracht1/"))

    #response code 200 betekent ok
    #dus als de request ok is word de json geprint
    #anders wordt de status code weergeven om problemen proberen op te sporen
    if response.status_code == 200:
        json_data = response.json()
        pprint.pprint(json_data)
    else:
        print(response)

def opdracht2():
    #tweede opdracht url met json response
    response = requests.post(url = (URL + "/opdracht2"),json = {
        "nr1":"Eerste regel",
        "nr2":"Tweede regel",
        "nr3":"Derde regel"
    })

    #als de request ok is wordt de json geprint en string voor de volgende opdracht
    #als return waarde gegeven
    #anders wordt de status code weergeven om problemen proberen op te sporen
    if response.status_code == 200:
        json_data = response.json()
        pprint.pprint(json_data)
        return json_data['string']
    else:
        print(response)

def opdracht3(string):

    #string van de vorige response omzetten naar bytes met utf-8 encoding
    byte_string = bytes(string,"utf-8")

    #deze bytestring omzetten naar hexadecimaal
    hex_string = byte_string.hex()

    #hexstring wordt meegegeven met de post request
    response = requests.post(url = (URL + "/opdracht3/" + hex_string))

    #als de request ok is wordt de json geprint en string voor de volgende opdracht
    #als return waarde gegeven
    #anders wordt de status code weergeven om problemen proberen op te sporen
    if response.status_code == 200:
        json_data = response.json()
        pprint.pprint(json_data)
        return json_data['string']
    else:
        print(response)

def opdracht4(string):

    #string van de vorige response omzetten naar bytes met utf-8 encoding
    byte_string = bytes(string,"utf-8")

    #bytestring omzetten naar base64
    b64_string = base64.b64encode(byte_string)

    #base64 bytestring omzetten naar text met ascii encoding om deze mee te kunnen geven
    #met de post request
    response = requests.post(url = (URL + "/opdracht4/" + (b64_string.decode("ascii"))))


    #als de request ok is wordt de json geprint en de relative pad van het bestand
    #voor de volgende opdracht wordt gereturned
    #anders wordt de status code weergeven om problemen proberen op te sporen
    if response.status_code == 200:
        json_data = response.json()
        pprint.pprint(json_data)
        return json_data['relatieve_url']
    else:
        print(response)

def opdracht5(relative_url):

    #download het bestand voor deze opdracht
    download_file(relative_url)

    #maak een lege lijst aan
    file_list = []

    #open het bestand en lees het in
    #gebruikt hashlib om de SHA-512 hash te berekenen en zet deze om naar hexidacimaal
    #zodat deze kan doorgestuurd worden
    filename = "opdracht5.txt"
    readFile = open(filename, 'rb').read()
    file_hash = hashlib.sha512(readFile)
    hash = file_hash.hexdigest()

    response = requests.post(url = (URL + "/opdracht5/"), json={"sha512":hash})


    #als de request ok is wordt de json geprint en van alle relatieve urls worden de bestanden
    #gedownload , alle namen van de bestanden en de MD5 checksum worden aan een lijst toegevoegt
    #en als return waarde gegeven
    #anders wordt de status code weergeven om problemen proberen op te sporen
    if response.status_code == 200:
        json_data = response.json()
        pprint.pprint(json_data)
        for i in range(len(json_data['bestanden'])):
            download_file2(json_data['bestanden'][i]['relatieve_url'])
            file_list.append(json_data['bestanden'][i]['relatieve_url'].split('5/')[1])
        file_list.append(json_data["md5_checksum"])
        return file_list
    else:
        print(response)


def opdracht6(file_list):
    #het laatste element van de file list is de md5 hash en die wordt hier uit de lijst gehaald
    md5hash = file_list.pop()

    #Elk bestand in de filelist wordt geopent en de md5 hash berekent
    #als deze overeenkomt wordt het relative pad als oplossing doorgestuurd
    for file in file_list:
        readFile = open(file, 'rb').read()
        file_hash = hashlib.md5(readFile)
        hash = file_hash.hexdigest()

        if(hash == md5hash):
            response = requests.post(url = (URL + "/opdracht6/"), json={"relatieve_url":("/static/opdracht5/" + file)})

            #als we een goede response krijgen wordt het bericht eruit gehaald voor de volgende opdracht
            if response.status_code == 200:

                json_data = response.json()
                pprint.pprint(json_data)
                return json_data['bericht']
            else:
                print(response)


def opdracht7(message):

    #bericht opzetten naar bytes
    data = bytes(message,"utf-8")
    #willekeurige key van 32 Bytes (= 32 * 8 Bits = 256 Bits) genereren
    key = get_random_bytes(32)
    #cipher opstellen op basis van de key & het bericht versleutelen
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext,tag = cipher.encrypt_and_digest(data)

    #Het versleutelt bericht de key & nonce worden in hexidecimaal doorgestuurd
    response = requests.post(url = (URL + "/opdracht7/"), json={
            "bericht_versleuteld": str(ciphertext.hex()),
             "sleutel" : str(key.hex()),
              "nonce" : str(cipher.nonce.hex())
              })

    if response.status_code == 200:
        json_data = response.json()
        pprint.pprint(json_data)
        return
    else:
        print(response)


def opdracht8():

    message = "Kdg"
    #nieuw sleutelpaar genereren
    key = RSA.generate(2048)

    #publieke en private key opslaan
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    #het bericht versleutelen met de publieke sleutel
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))
    encrypted_data = cipher_rsa.encrypt(bytes(message,"utf-8"))

    #de sleutel en het versleutelt beticht in hexadecimaal doorsturen
    response = requests.post(url = (URL + "/opdracht8/"), json={
        "encrypted_data": encrypted_data.hex(),
         "prive_sleutel" : private_key.hex()
    })
    if response.status_code == 200:
        json_data = response.json()
        pprint.pprint(json_data)
        return
    else:
        print(response)




def download_file(relative_url):
    response = requests.get(url = (URL + relative_url))
    open("opdracht5.txt","wb").write(response.content)

def download_file2(relative_url):
    response = requests.get(url = (URL + relative_url))
    #splits de relatieve url op om aan de filename te geraken
    #bv. "/static/opdracht5/applicatie_jos.exe" => [""/static/opdracht","applicatie_jos.exe"]
    filename = response.url.split('5/')[1]
    open(filename,"wb").write(response.content)

def main():
    opdracht1()
    print("\n\n\n")
    op3_string = opdracht2()
    print("\n\n\n")
    op4_string = opdracht3(op3_string)
    print("\n\n\n")
    op5_url = opdracht4(op4_string)
    print("\n\n\n")
    file_list = opdracht5(op5_url)
    print("\n\n\n")
    message = opdracht6(file_list)
    print("\n\n\n")
    opdracht7(message)
    print("\n\n\n")
    opdracht8()



if __name__ == "__main__":
    main()
