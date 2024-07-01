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

### Overview:

The project consists of the following main components:

- [**app.py**](http://app.py/): Main application entry point.
- **templates/**: HTML templates for rendering web pages.
- **static/**: Static files (e.g., CSS, images) used in the application.

    instance
  migrations
  static
  templates
  __pycache__
  migrations  versions
  migrations  __pycache__
  migrations  versions  __pycache__
  static  admin
  static  dashboard-css
  static  formscss
  static  images
  static  img
  static  js
  static  licenses
  static  mdb
  static  petcss
  static  uploads
  static  vets
  static  img  curved-images
  static  img  illustrations
  static  img  logos
  static  img  shapes
  static  img  small-logos
  static  img  theme
  static  mdb  css
  static  mdb  img
  static  mdb  js
  static  mdb  src
  static  mdb  src  js
  static  mdb  src  scss
  static  mdb  src  js  autoinit
  static  mdb  src  js  bootstrap
  static  mdb  src  js  free
  static  mdb  src  js  mdb
  static  mdb  src  js  autoinit  callbacks
  static  mdb  src  js  autoinit  initSelectors
  static  mdb  src  js  bootstrap  dist
  static  mdb  src  js  bootstrap  mdb-prefix
  static  mdb  src  js  bootstrap  src
  static  mdb  src  js  bootstrap  dist  dom
  static  mdb  src  js  bootstrap  dist  util
  static  mdb  src  js  bootstrap  mdb-prefix  dom
  static  mdb  src  js  bootstrap  mdb-prefix  util
  static  mdb  src  js  bootstrap  src  dom
  static  mdb  src  js  bootstrap  src  util
  static  mdb  src  js  mdb  dom
  static  mdb  src  js  mdb  perfect-scrollbar
  static  mdb  src  js  mdb  util
  static  mdb  src  js  mdb  perfect-scrollbar  handlers
  static  mdb  src  js  mdb  perfect-scrollbar  lib
  static  mdb  src  js  mdb  util  touch
  static  mdb  src  scss  bootstrap
  static  mdb  src  scss  bootstrap-rtl-fix
  static  mdb  src  scss  custom
  static  mdb  src  scss  free
  static  mdb  src  scss  bootstrap  forms
  static  mdb  src  scss  bootstrap  helpers
  static  mdb  src  scss  bootstrap  mixins
  static  mdb  src  scss  bootstrap  utilities
  static  mdb  src  scss  bootstrap  vendor
  static  mdb  src  scss  bootstrap-rtl-fix  forms
  static  mdb  src  scss  bootstrap-rtl-fix  helpers
  static  mdb  src  scss  bootstrap-rtl-fix  mixins
  static  mdb  src  scss  bootstrap-rtl-fix  utilities
  static  mdb  src  scss  bootstrap-rtl-fix  vendor
  static  mdb  src  scss  free  forms
  static  mdb  src  scss  free  mixins
  templates  admin
  templates  base
  templates  emails
  templates  forms
  templates  petForms
  templates  soft-ui-dashboard-main
  templates  vets
  templates  petForms  viewPets
  templates  petForms  viewProfile
  templates  soft-ui-dashboard-main  assets
  templates  soft-ui-dashboard-main  docs
  templates  soft-ui-dashboard-main  media
  templates  soft-ui-dashboard-main  pages
  templates  soft-ui-dashboard-main  assets  css
  templates  soft-ui-dashboard-main  assets  fonts
  templates  soft-ui-dashboard-main  assets  img
  templates  soft-ui-dashboard-main  assets  js
  templates  soft-ui-dashboard-main  assets  scss
  templates  soft-ui-dashboard-main  assets  img  curved-images
  templates  soft-ui-dashboard-main  assets  img  illustrations
  templates  soft-ui-dashboard-main  assets  img  logos
  templates  soft-ui-dashboard-main  assets  img  shapes
  templates  soft-ui-dashboard-main  assets  img  small-logos
  templates  soft-ui-dashboard-main  assets  img  theme
  templates  soft-ui-dashboard-main  assets  js  core
  templates  soft-ui-dashboard-main  assets  js  plugins
  templates  soft-ui-dashboard-main  assets  scss  soft-ui-dashboard
  templates  soft-ui-dashboard-main  assets  scss  soft-ui-dashboard  bootstrap
  templates  soft-ui-dashboard-main  assets  scss  soft-ui-dashboard  cards
  templates  soft-ui-dashboard-main  assets  scss  soft-ui-dashboard  custom
  templates  soft-ui-dashboard-main  assets  scss  soft-ui-dashboard  forms
  templates  soft-ui-dashboard-main  assets  scss  soft-ui-dashboard  mixins
  templates  soft-ui-dashboard-main  assets  scss  soft-ui-dashboard  plugins
  templates  soft-ui-dashboard-main  assets  scss  soft-ui-dashboard  variables
  templates  soft-ui-dashboard-main  assets  scss  soft-ui-dashboard  bootstrap  forms
  templates  soft-ui-dashboard-main  assets  scss  soft-ui-dashboard  bootstrap  helpers
  templates  soft-ui-dashboard-main  assets  scss  soft-ui-dashboard  bootstrap  mixins
  templates  soft-ui-dashboard-main  assets  scss  soft-ui-dashboard  bootstrap  utilities
  templates  soft-ui-dashboard-main  assets  scss  soft-ui-dashboard  bootstrap  vendor
  templates  soft-ui-dashboard-main  assets  scss  soft-ui-dashboard  plugins  free


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
