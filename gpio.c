#include <stdio.h>
#include <gpiod.h>

int main() {
	struct gpiod_chip *chip;
	struct gpiod_line *line;
	int req, value;

	chip = gpiod_chip_open("/dev/gpiochip0");
	if (!chip)
		return -1;

	line = gpiod_chip_get_line(chip, 8);
	if (!line) {
		gpiod_chip_close(chip);
		return -1;
	}

	/*req = gpiod_line_request_input(line, "gpio_state");
	if (req) {
		gpiod_chip_close(chip);
		return -1;
	}

	value = gpiod_line_get_value(line);

	printf("GPIO value is: %d\n", value);*/

	req = gpiod_line_request_output(line, "gpio_state", 1);
	if (req) {
		gpiod_chip_close(chip);
		return -1;
	}

	req = gpiod_line_set_value(line, 0);
	if (req) {
		gpiod_chip_close(chip);
		return -1;
	}

	req = gpiod_line_set_value(line, 1);
	if (req) {
		gpiod_chip_close(chip);
		return -1;
	}

	/*req = gpiod_line_request_input(line, "gpio_state");
	if (req) {
		gpiod_chip_close(chip);
		return -1;
	}

	value = gpiod_line_get_value(line);

	printf("GPIO value is: %d\n", value);*/

	printf("OK.\n");

	gpiod_chip_close(chip);
}
