from flask import Flask, request, jsonify, Response


class Endpoint():
    def __init__(self, port: str):
        self._app = Flask(__name__)
        self._port = port

        @self._app.route('/ping', methods=['POST'])
        def add_message():
            content = request.get_json()
            print(content)  # Do your processing
            return Response(status=200)

    def runServer(self):
        self._app.run(host="0.0.0.0", port=self._port)


if __name__ == '__main__':
    ep = Endpoint("5100")
    ep.runServer()
