# PWM v2 REDUX: Python Website Manager

PWM is a powerful, self-hosted website manager that allows you to create, manage, and edit your web projects directly from a web-based interface. It's the perfect tool for developers, hobbyists, and anyone who wants a simple yet flexible way to manage multiple websites on a single server.

## Key Features

* **Multi-User Support**: Create accounts for different users, each with their own isolated space for managing websites.
* **Live Editor**: A built-in code editor with live preview for HTML, CSS, and JavaScript files, allowing you to see your changes in real-time.
* **File Manager**: A comprehensive file manager to upload, download, rename, and organize your project files.
* **Backup and Restore**: Automatically creates backups as you save, and allows you to download a complete zip backup of your entire site.
* **Admin Panel**: An admin panel to manage users and configure application settings.
* **Autostart**: Configure websites to start automatically when the server boots up.

## Installation

1.  **Clone the repository**:
    ```bash
    git clone [https://github.com/your-username/PWM.git](https://github.com/your-username/PWM.git)
    cd PWM
    ```
2.  **Run the installer**:
    ```bash
    bash install.sh
    ```
3.  **Enable and start the service**:
    ```bash
    sudo systemctl daemon-reload
    sudo systemctl enable --now pwm.service
    ```

## Usage

Once the service is running, you can access the PWM dashboard by navigating to `http://your-server-ip:5000` in your web browser. From there, you can create a new account and start managing your websites.
