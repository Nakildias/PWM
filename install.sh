#!/bin/bash

# Define paths
INSTALL_DIR="$HOME/.local/share/pwm"
VENV_DIR="$INSTALL_DIR/venv"
RUN_SCRIPT="/usr/local/bin/pwm.sh"
# Change service file directory to system-wide
SERVICE_FILE_DIR="/etc/systemd/system"
SERVICE_FILE_PATH="$SERVICE_FILE_DIR/pwm.service"
REQUIREMENTS_FILE="$INSTALL_DIR/requirements.txt"

echo "Starting PWM installer..."

# Get the current user's username for the systemd service
CURRENT_USER=$(whoami)

# 1. Create installation directory
echo "Creating installation directory: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR" || { echo "Failed to create installation directory."; exit 1; }

# 2. Copy Python files and templates (assuming they are in the current directory)
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

# 6. Create systemd system service file
echo "Creating systemd system service file at $SERVICE_FILE_PATH..."
# This operation requires sudo as it's writing to /etc/systemd/system
cat <<EOF | sudo tee "$SERVICE_FILE_PATH" > /dev/null
[Unit]
Description=Python Website Manager
After=network.target

[Service]
ExecStart=/usr/local/bin/pwm.sh
# WorkingDirectory should be the absolute path to the PWM application files
WorkingDirectory=$INSTALL_DIR
# Run the service as the user who installed it, or specify a dedicated user
User=$CURRENT_USER
Group=$CURRENT_USER # Optional, but good practice
StandardOutput=journal
StandardError=journal
Restart=always

[Install]
WantedBy=multi-user.target
EOF
echo "Service file created."

echo ""
echo "---------------------------------------------------------"
echo "PWM installation complete!"
echo "To manage the PWM service, please run the following commands (requires sudo):"
echo "sudo systemctl daemon-reload"
echo "sudo systemctl enable --now pwm.service"
echo ""
echo "To check the service status:"
echo "sudo systemctl status pwm.service"
echo ""
echo "To stop the service:"
echo "sudo systemctl stop pwm.service"
echo ""
echo "To view logs:"
echo "journalctl -u pwm.service -f"
echo "---------------------------------------------------------"
