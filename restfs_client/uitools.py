#!/usr/bin/env python3

'''
    RestFS client: tools for the UI
'''

import getpass

from restfs_common.constants import ADMIN


def ask_login_process(pre_input, confirm_password=False, interactive=True):
    '''Ask for login/password'''
    pre_input = pre_input.split()
    if len(pre_input) < 2 and not interactive:
        raise ValueError('Missing user and password values in non-interactive mode')

    try:
        username = pre_input[0]
    except IndexError:
        username = input('Enter username: ')

    try:
        password = pre_input[1]
    except IndexError:
        if username == ADMIN:
            password = input('Enter administrator token: ')
        else:
            password = getpass.getpass('Enter password: ')
    if confirm_password and interactive:
        password_confirmation = getpass.getpass('Confirm password: ')
        if password != password_confirmation:
            raise ValueError('Passwords does not match')

    return username, password

def ask_string(prompt, pre_input=None, echo=True, interactive=True):
    '''Ask for a simple string'''
    if not pre_input and not interactive:
        raise ValueError(f'Cannot ask "{prompt}" in non-interactive mode')

    if pre_input:
        response = pre_input
    else:
        response = input(prompt) if echo else getpass.getpass(prompt)

    if not echo:
        confirmation = getpass.getpass('Confirm answer: ')
        if response != confirmation:
            raise ValueError('Value does not match')

    return response

def ask_integer(prompt, pre_input='', max_value=None, interactive=True):
    '''Ask for an integer. Range is optional.'''
    if not pre_input and not interactive:
        raise ValueError(f'Cannot ask "{prompt}" in non-interactive mode')
    prefix = ''
    response = None
    if pre_input:
        try:
            response = int(pre_input)
        except ValueError:
            pass
    while True:
        if not response:
            try:
                response = int(input(f'{prefix}{prompt}'))
            except ValueError:
                prefix = 'Invalid integer, try again. '
                continue
        if max_value:
            if response not in range(1, max_value + 1):
                prefix = f'Integer not in the range [1, {max_value}], try again. '
                response = None
                continue
        return response

def ask_choice(choices, pre_input='', interactive=True, out_func=None):
    '''Ask for a choice'''
    if out_func is None:
        out_func = print

    if len(choices) == 1:
        return choices[0]

    if pre_input:
        try:
            choice = int(pre_input)
            if choice in range(1, len(choices) + 1):
                return choices[choice - 1]
        except ValueError as error:
            if pre_input in choices:
                return pre_input

    if not interactive:
        raise ValueError('Invalid value, cannot ask for new in non-interactive')

    show_choices = True
    while True:
        if show_choices:
            out_func('Please, select one of:')
            for choice_num, choice in enumerate(choices, start=1):
                out_func(f' {choice_num}. {choice}')
        show_choices = False
        choice = input(f'Enter number (1-{len(choices)}): ')
        if choice == '':
            show_choices = True
            continue
        try:
            choice = int(choice)
        except ValueError:
            out_func('Invalid number, try again')
            continue
        if choice not in range(1, len(choices) + 1):
            out_func('Number not in range, try again')
            continue
        return choices[choice - 1]
