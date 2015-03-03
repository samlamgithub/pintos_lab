################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
O_SRCS += \
../src/examples/bubsort.o \
../src/examples/cat.o \
../src/examples/cmp.o \
../src/examples/cp.o \
../src/examples/echo.o \
../src/examples/halt.o \
../src/examples/hex-dump.o \
../src/examples/insult.o \
../src/examples/lineup.o \
../src/examples/matmult.o \
../src/examples/mcat.o \
../src/examples/mcp.o \
../src/examples/recursor.o \
../src/examples/rm.o 

C_SRCS += \
../src/examples/bubsort.c \
../src/examples/cat.c \
../src/examples/cmp.c \
../src/examples/cp.c \
../src/examples/echo.c \
../src/examples/halt.c \
../src/examples/hex-dump.c \
../src/examples/insult.c \
../src/examples/lineup.c \
../src/examples/matmult.c \
../src/examples/mcat.c \
../src/examples/mcp.c \
../src/examples/recursor.c \
../src/examples/rm.c 

OBJS += \
./src/examples/bubsort.o \
./src/examples/cat.o \
./src/examples/cmp.o \
./src/examples/cp.o \
./src/examples/echo.o \
./src/examples/halt.o \
./src/examples/hex-dump.o \
./src/examples/insult.o \
./src/examples/lineup.o \
./src/examples/matmult.o \
./src/examples/mcat.o \
./src/examples/mcp.o \
./src/examples/recursor.o \
./src/examples/rm.o 

C_DEPS += \
./src/examples/bubsort.d \
./src/examples/cat.d \
./src/examples/cmp.d \
./src/examples/cp.d \
./src/examples/echo.d \
./src/examples/halt.d \
./src/examples/hex-dump.d \
./src/examples/insult.d \
./src/examples/lineup.d \
./src/examples/matmult.d \
./src/examples/mcat.d \
./src/examples/mcp.d \
./src/examples/recursor.d \
./src/examples/rm.d 


# Each subdirectory must supply rules for building sources it contributes
src/examples/%.o: ../src/examples/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


