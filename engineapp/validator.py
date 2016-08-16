def valid_day(day):
    for d in day:
        if d.isdigit()!=True:
            return None
    return int(day) if int(day) and int(day)<32 else None

def valid_year(year):
    return int(year) if year.isdigit()and int(year) >=1900 and int(year) <= 2020 else None

months = ['January',
          'February',
          'March',
          'April',
          'May',
          'June',
          'July',
          'August',
          'September',
          'October',
          'November',
          'December']

def valid_month(month):
    # print (month.title())
    if month.title() in months:
        return month.title()
    else:
        return None
