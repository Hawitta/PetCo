# PetCo: Pet Healthcare Management System

## License

[![License: COZE](https://img.shields.io/badge/License-COZE-brightgreen.svg)](https://www.coze.com/docs/guides/osn?_lang=en)

The Coze Bot SDK in this project is licensed under Coze  [LICENSE.md](notion://www.notion.so/link/to/your/LICENSE.md) for details.

The Pet Healthcare Management System is a Flask-based web application designed to manage the health records of pets efficiently. It allows pet owners and veterinarians to register pets, schedule appointments, track medical histories, and manage treatments all in one place. This system aims to simplify pet healthcare management, ensuring timely care and accurate record-keeping.

<br />

# Project Setup/Installation Instructions:

## Dependencies:

- Flask
- SQLAlchemy
- WTForms
- OAuthlib
- Matplotlib

# Installation Steps:

1. Clone the repository from GitHub

```bash
git clone <https://github.com/Hawitta/PetCo.git>

```

1. Navigate to project folder

```bash
  cd petco

```

1. Install dependencies:

```bash
pip install -r requirements.txt

```
<br />

# Usage Instructions

## How to run

1. Ensure you are in the project directory
2. Run the Flask application in the terminal

```bash
flask run

```

1. Open a web browser and go to `http://localhost:5000` to view the application.

### Examples:

- **Register a Pet:** Fill out the registration form with pet details.
- **Schedule an Appointment:** Navigate to the profile drop-down menu and select appointment, use the button to redirect to book appointment form.

### Input/Output:

- **Input:** Users input pet details and appointment information via web forms.
- **Output:** The application displays confirmation messages, updates to pet records, and appointment schedules.

<br />

# Project Structure:

```markdown-tree
<pre>

D:.
+---instance
+---migrations
|   +---versions
|   |   +---__pycache__
|   +---__pycache__
+---static
|   +---admin
|   +---dashboard-css
|   +---formscss
|   +---images
|   +---img
|   +---js
|   +---licenses
|   +---mdb
|   +---petcss
|   +---uploads
|   +---vets
+---templates
|   +---admin
|   +---base
|   +---emails
|   +---forms
|   +---petForms
|   |   +---viewPets
|   |   +---viewProfile
|   +---soft-ui-dashboard-main
|       +---assets
|       +---docs
|       +---media
|       +---pages
|   +---vets
+---__pycache__

```

### Overview:

The project consists of the following main components:

- [**app.py**](http://app.py/): Main application entry point.
- **templates/**: HTML templates for rendering web pages.
- **static/**: Static files (e.g., CSS, images) used in the application.

  
### Key Files:

- [**app.py**](http://app.py/): Flask application setup and routes.
- [**forms.py**](http://forms.py/): Defines SQLAlchemy forms for registration, login and appointments
- [**models.py**](http://models.py/): Defines SQLAlchemy models for pets, owners, appointments, etc.
- [**forms.py**](http://forms.py/): WTForms used for form validation and rendering.
- **templates/**: Contains HTML templates using Jinja2 templating engine.
- **static/**: CSS, images, and other static assets.

<br />

## Acknowledgements

- [Building an AI Chatbot with Coze](https://www.youtube.com/watch?v=KLpMdzHxG1A)
- [Google Authentication with Flask](https://www.youtube.com/watch?v=FydJC3aP7mM)
- [Data Visualization with Python](https://www.youtube.com/watch?v=a9UrKTVEeZA)

<br />

## Contact Us

For support,question or contribution email [iamhawiana@gmail.com](mailto:iamhawiana@gmail.com) or create an issue in this repository. This is the fastest way to reach out. Happy Coding!
