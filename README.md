Voor je begint, test je eerst of je de originele server kan starten op je eigen computer. Dit doe je door volgende stappen in volgorde uit te voeren:
* je maakt een virtuele Python (3.7+) omgeving aan en activeert deze meteen (https://packaging.python.org/guides/installing-using-pip-and-virtual-environments/)
* je installeert de volgende packages via pip: fastapi uvicorn aiofiles python-multipart pycryptodome
* je gaat in je CLI naar de 'server' folder
* je voert volgend commando uit: uvicorn app.main:app --host 0.0.0.0 --port 8000
* de treasure server wordt nu gehost op je eigen computer op poort 8000

Je kan er ook voor kiezen om de server in een docker container te draaien. Het commando dat je daarvoor nodig hebt is: 'docker-compose up -d'. Dit commando voer je uit in de folder waar de docker-compose.yml zich bevindt (deze folder). Verder hoef je niets te doen en zorgt docker(-compose) voor de juiste setup (package installs etc.). In de YAML file kan je nakijken op welke poort je server zal luisteren.