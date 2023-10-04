D_BUILD		?=	build
D_SRC		:=	src
D_INCLUDE 	:=	include
OUT			?=	pwm

CC 			:=	gcc
LD 			:=	gcc

SRC_C		:=	$(shell find $(D_SRC) -name '*.c')
OBJ_C		:=	$(subst $(D_SRC), $(D_BUILD), $(SRC_C:%.c=%.c.o))

CFLAGS	 	:=	-Werror -Wall -Wextra -c -std=c11 -I$(D_INCLUDE) $(shell pkg-config --cflags openssl)
LDFLAGS		:=	$(shell pkg-config --libs openssl) -lpthread

.PHONY: all clean debug

default: always $(OUT)

all: always clean $(OUT)

run: always $(OUT)
	@printf "\e[1;32m  Running\e[0m $(OUT)\n"
	@./$(OUT) test.pwm MyPassword dd

debug: CFLAGS += -DDEBUG -g
debug: debug_before all
debug_before:
	@printf "\e[1;32mBuilding\e[0m with \e[1;31mdebug\e[0m flags\n"

trace: CFLAGS += -DDEBUG -DDEBUG_TRACE -g
trace: trace_before all
trace_before:
	@printf "\e[1;32mBuilding\e[0m with \e[1;31mdebug\e[0m and \e[1;31mtrace\e[0m flags\n"

$(OUT) : $(OBJ_C)
	@printf "\e[1;32m  Building\e[0m $(notdir $@)\n"
	@$(LD) $(OBJ_C) -o $@ $(LDFLAGS)

$(D_BUILD)/%.c.o: $(D_SRC)/%.c
	@mkdir -p $(dir $@)
	@printf "\e[1;32m  Compiling\e[0m $(notdir $<)\n"
	@$(CC) -o $@ $(CFLAGS) $<

clean:
	@printf "\e[1;32m  Cleaning\e[0m\n"
	@rm -rf $(D_BUILD)/*

always:
	@mkdir -p $(D_BUILD)