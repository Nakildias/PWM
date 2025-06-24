#!/bin/bash

# Define paths
INSTALL_DIR="$HOME/.local/share/pwm"
VENV_DIR="$INSTALL_DIR/venv"
RUN_SCRIPT="/usr/local/bin/pwm.sh"
SERVICE_FILE_DIR="$HOME/.config/systemd/user"
SERVICE_FILE_PATH="$SERVICE_FILE_DIR/pwm.service"
REQUIREMENTS_FILE="$INSTALL_DIR/requirements.txt"

echo "Starting PWM installer..."

# 1. Create installation directory
echo "Creating installation directory: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR" || { echo "Failed to create installation directory."; exit 1; }

# 2. Copy Python files and templates
echo "Copying application files to $INSTALL_DIR..."
cp "config.py" "$INSTALL_DIR/" || { echo "Failed to copy config.py."; exit 1; }
cp "README.md" "$INSTALL_DIR/" || { echo "Failed to copy README.md."; exit 1; }
cp "requirements.txt" "$INSTALL_DIR/" || { echo "Failed to copy requirements.txt."; exit 1; }
cp "run.py" "$INSTALL_DIR/" || { echo "Failed to copy run.py."; exit 1; }
cp "websites.py" "$INSTALL_DIR/" || { echo "Failed to copy websites.py."; exit 1; }
cp -r "templates" "$INSTALL_DIR/" || { echo "Failed to copy templates directory."; exit 1; }
echo "Files copied."

# 3. Create virtual environment
echo "Creating Python virtual environment at $VENV_DIR..."
python3 -m venv "$VENV_DIR" || { echo "Failed to create virtual environment. Ensure python3-venv is installed or try running 'sudo apt install python3-venv' or equivalent for your distribution."; exit 1; }
echo "Virtual environment created."

# 4. Install dependencies
echo "Installing Python dependencies from requirements.txt..."
"$VENV_DIR/bin/pip" install -r "$REQUIREMENTS_FILE" || { echo "Failed to install dependencies. Check network connection or dependencies in requirements.txt."; exit 1; }
echo "Dependencies installed."

# 5. Create pwm.sh script
echo "Creating runner script at $RUN_SCRIPT..."
# Using sudo tee to write to /usr/local/bin which requires root privileges
echo "#!/bin/bash
PWM_INSTALL_DIR=\"$HOME/.local/share/pwm\"
VENV_PYTHON=\"\$PWM_INSTALL_DIR/venv/bin/python\"
\"\$VENV_PYTHON\" \"\$PWM_INSTALL_DIR/run.py\"
" | sudo tee "$RUN_SCRIPT" > /dev/null || { echo "Failed to create $RUN_SCRIPT. Root privileges are required."; exit 1; }
sudo chmod +x "$RUN_SCRIPT" || { echo "Failed to make $RUN_SCRIPT executable."; exit 1; }
echo "Runner script created and made executable."

# 6. Create systemd user service file
echo "Creating systemd user service file at $SERVICE_FILE_PATH..."
mkdir -p "$SERVICE_FILE_DIR" || { echo "Failed to create service file directory. Check permissions."; exit 1; }
cat <<EOF > "$SERVICE_FILE_PATH"
[Unit]
Description=Python Website Manager
After=network.target

[Service]
ExecStart=/usr/local/bin/pwm.sh
WorkingDirectory=%h/.local/share/pwm
StandardOutput=journal
StandardError=journal
Restart=always
# The service runs as the user who enables it via systemctl --user

[Install]
WantedBy=default.target
EOF
echo "Service file created."

echo ""
echo "---------------------------------------------------------"
echo "PWM installation complete!"
echo "To start the PWM service, please run the following commands:"
echo "systemctl --user daemon-reload"
echo "systemctl --user enable --now pwm.service"
echo ""
echo "To check the service status:"
echo "systemctl --user status pwm.service"
echo ""
echo "To stop the service:"
echo "systemctl --user stop pwm.service"
echo ""
echo "To view logs:"
echo "journalctl --user -u pwm.service -f"
echo "---------------------------------------------------------"
