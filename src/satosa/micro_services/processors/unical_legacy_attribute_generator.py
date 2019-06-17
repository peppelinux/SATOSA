import re
from .base_processor import BaseProcessor


class UniAttributeProcessor:
    @staticmethod
    def codice_fiscale_rs(schacpersonaluniqueids=[], nationprefix=False, nationprefix_sep=':'):
        if isinstance(schacpersonaluniqueids, str):
            schacpersonaluniqueids = [schacpersonaluniqueids]
        # R&S format
        rs_regexp = (r'(?P<urn_prefix>urn:schac:personalUniqueID:)?'
                     r'(?P<nation>[a-zA-Z]{2}):'
                     r'(?P<doc_type>[a-zA-Z]{2,3}):(?P<uniqueid>[\w]+)')
        for uniqueid in schacpersonaluniqueids:
            result = re.match(rs_regexp, uniqueid, re.I)
            if result:
                data = result.groupdict()
                #if data.get('nation') == 'IT' and data.get('doc_type') in  ['CF', 'TIN']:
                if nationprefix:
                    # returns IT:CODICEFISCALE
                    return nationprefix_sep.join((data['nation'], data['uniqueid']))
                # returns CODICEFISCALE
                return data['uniqueid']

    @staticmethod
    def codice_fiscale_spid(fiscalNumbers, nationprefix=False, nationprefix_sep=':'):
        if isinstance(fiscalNumbers, str):
            fiscalNumbers = [fiscalNumbers]
        # SPID/eIDAS FORMAT
        spid_regexp = r'(?P<prefix>TIN)(?P<nation>[a-zA-Z]{2})-(?P<uniqueid>[\w]+)'
        for fiscalNumber in fiscalNumbers:
            result = re.match(spid_regexp, fiscalNumber, re.I)
            if result:
                data = result.groupdict()
                if nationprefix:
                    # returns IT:CODICEFISCALE
                    return nationprefix_sep.join((data['nation'], data['uniqueid']))
                # returns CODICEFISCALE
                return data['uniqueid']

    @staticmethod
    def matricola(personalUniqueCodes=[], id_string='dipendente'):
        if isinstance(personalUniqueCodes, str):
            personalUniqueCodes = [personalUniqueCodes]
        _regexp = (r'(?P<urn_prefix>urn:schac:personalUniqueCode:)?'
                   r'(?P<nation>[a-zA-Z]{2}):'
                   r'(?P<organization>[a-zA-Z\.\-]+):'
                   'IDSTRING:'
                   r'(?P<uniqueid>[\w]+)').replace('IDSTRING', id_string)
        for uniqueid in personalUniqueCodes:
            result = re.match(_regexp, uniqueid, re.I)
            if result:
                return result.groupdict()['uniqueid']


class UnicalLegacyAttributeGenerator(BaseProcessor):

    def matricola_dipendente(self, attributes):
        if attributes.get('schacpersonaluniquecode'):
            return UniAttributeProcessor.matricola(attributes['schacpersonaluniquecode'], id_string='dipendente')

    def matricola_studente(self, attributes):
        if attributes.get('schacpersonaluniquecode'):
            return UniAttributeProcessor.matricola(attributes['schacpersonaluniquecode'], id_string='studente')

    def codice_fiscale(self, attributes):
        if attributes.get('schacpersonaluniqueid'):
            return UniAttributeProcessor.codice_fiscale_rs(attributes['schacpersonaluniqueid'])
        elif attributes.get('fiscalNumber'):
            fiscalNumber = UniAttributeProcessor.codice_fiscale_spid(attributes['fiscalNumber'])
            # put a fake 'schacpersonaluniqueid' to do ldap account linking with the next microservice
            attributes['schacpersonaluniqueid'] = 'urn:schac:personalUniqueID:IT:CF:{}'.format(fiscalNumber)
            return fiscalNumber

    def process(self, internal_data, attribute, **kwargs):
        if hasattr(self, attribute) and callable(getattr(self, attribute)):
            internal_data.attributes[attribute] = getattr(self, attribute)(internal_data.attributes)
